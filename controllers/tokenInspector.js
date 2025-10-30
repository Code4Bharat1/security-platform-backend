// controllers/oauthTokenController.js

/**
 * OAuth Token Inspector Controller
 * Decodes and analyzes JWT tokens without signature verification
 */

export const testToken = async (req, res) => {
    try {
        const { token } = req.body;

        // ============ INPUT VALIDATION ============
        if (!token || typeof token !== 'string' || !token.trim()) {
            return res.status(400).json({
                error: 'Token is required and must be a non-empty string',
            });
        }

        const trimmedToken = token.trim();

        // Basic JWT format check (3 parts separated by dots)
        if (!/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(trimmedToken)) {
            return res.status(400).json({
                error: 'Invalid JWT format. Expected: header.payload.signature',
            });
        }

        // ============ DECODE TOKEN ============
        let header, payload;

        try {
            const parts = trimmedToken.split('.');

            // Decode header
            const headerJson = Buffer.from(parts[0], 'base64').toString('utf-8');
            header = JSON.parse(headerJson);

            // Decode payload
            const payloadJson = Buffer.from(parts[1], 'base64').toString('utf-8');
            payload = JSON.parse(payloadJson);
        } catch (decodeError) {
            return res.status(400).json({
                error: `Failed to decode token: ${decodeError.message}`,
            });
        }

        // ============ ANALYZE TOKEN ============
        const now = Math.floor(Date.now() / 1000);
        const issues = [];
        let score = 100;
        const scoreBreakdown = [];

        // Helper to penalize
        const penalize = (label, points) => {
            score -= points;
            scoreBreakdown.push({ label, delta: -points });
        };

        // Extract timestamps
        const expEpoch = payload.exp || null;
        const iatEpoch = payload.iat || null;

        // Check for missing critical claims
        if (!('exp' in payload)) {
            issues.push('Missing "exp" (expiration) claim');
            penalize('Missing exp', 25);
        }

        if (!('iat' in payload)) {
            issues.push('Missing "iat" (issued at) claim');
            penalize('Missing iat', 10);
        }

        if (!('iss' in payload)) {
            issues.push('Missing "iss" (issuer) claim');
            penalize('Missing iss', 10);
        }

        if (!('sub' in payload)) {
            issues.push('Missing "sub" (subject) claim');
            penalize('Missing sub', 5);
        }

        // Check if token is expired
        let isExpired = false;
        if (expEpoch) {
            isExpired = now >= expEpoch;
            if (isExpired) {
                const expiredSince = now - expEpoch;
                issues.push(`Token expired ${formatDuration(expiredSince)} ago`);
                penalize('Token expired', 30);
            }
        }

        // Check algorithm
        if (header.alg) {
            const alg = String(header.alg).toLowerCase();
            if (alg === 'none') {
                issues.push('Critical: Algorithm is "none" - token is unsigned!');
                penalize('alg: none', 50);
            }
        }

        // Calculate lifetime percentage used
        let lifetimePercentUsed = null;
        if (expEpoch && iatEpoch && expEpoch > iatEpoch) {
            const lifetime = expEpoch - iatEpoch;
            const used = Math.min(Math.max(now - iatEpoch, 0), lifetime);
            lifetimePercentUsed = Math.round((used / lifetime) * 100);
        }

        // Ensure score is between 0-100
        score = Math.max(0, Math.min(100, score));

        // ============ BUILD RESPONSE ============
        return res.status(200).json({
            payload,
            header,
            issues,
            meta: {
                expEpoch,
                iatEpoch,
                isExpired,
                lifetimePercentUsed,
                securityScore: score,
                scoreBreakdown,
            },
        });

    } catch (error) {
        console.error('Token inspection error:', error);
        return res.status(500).json({
            error: 'Internal server error during token inspection',
        });
    }
};

/**
 * Format seconds into human-readable duration
 */
function formatDuration(seconds) {
    const abs = Math.abs(seconds);
    const d = Math.floor(abs / 86400);
    const h = Math.floor((abs % 86400) / 3600);
    const m = Math.floor((abs % 3600) / 60);
    const s = Math.floor(abs % 60);

    const parts = [];
    if (d > 0) parts.push(`${d}d`);
    if (h > 0) parts.push(`${h}h`);
    if (m > 0) parts.push(`${m}m`);
    if (s > 0 || parts.length === 0) parts.push(`${s}s`);

    return parts.join(' ');
}


