// controllers/secretKeyScanner.controller.js
import axios from 'axios';
import crypto from 'crypto';
import { SecretScan } from '../models/secretScanModel.js';

const rules = [
  { type: 'AWS Secret Access Key', regex: /aws_secret_access_key\s*=\s*["']?([A-Za-z0-9\/+=]{40})["']?/i, severity: 'Critical', suggestion: 'Revoke and rotate this key immediately. Prefer IAM roles / env vars.', provider: 'aws' },
  { type: 'JWT Secret', regex: /jwt[_-]?secret\s*=\s*["'](.{8,})["']/i, severity: 'High', suggestion: 'Store in a secret manager or environment variable; rotate if exposed.', provider: 'jwt' },
  { type: 'Generic API Key', regex: /api[_-]?key\s*=\s*["']?([\w-]{16,})["']?/i, severity: 'Medium', suggestion: 'Avoid hardcoding; restrict scope; rotate if exposed.', provider: 'generic' },
  { type: 'GitHub Token', regex: /(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}/, severity: 'High', suggestion: 'Revoke in GitHub → Developer Settings → Tokens and rotate.', provider: 'github' },
  { type: 'Stripe Secret Key', regex: /(sk_live|sk_test)_[A-Za-z0-9]{10,}/, severity: 'Critical', suggestion: 'Rotate in Stripe Dashboard; never commit live keys.', provider: 'stripe' },
  { type: 'OpenAI API Key', regex: /(sk-[A-Za-z0-9]{20,})/, severity: 'High', suggestion: 'Rotate the key and move it to a protected secret store.', provider: 'openai' },
  { type: 'Google API Key', regex: /AIza[0-9A-Za-z\-_]{35}/, severity: 'High', suggestion: 'Restrict the key (HTTP referrers / IPs) and rotate if leaked.', provider: 'google' },
];

const redact = (s) => !s ? s : (s.length <= 8 ? '****' : s.slice(0, 4) + '****' + s.slice(-4));

async function validateKeyOnline(provider, secret) {
  try {
    switch (provider) {
      case 'github': {
        const r = await axios.get('https://api.github.com/user', {
          headers: { Authorization: `token ${secret}`, 'User-Agent': 'SecScan/1.0' },
          validateStatus: () => true, timeout: 8000,
        });
        if (r.status === 200) return { status: 'valid', evidence: { status: 200 } };
        if (r.status === 401) return { status: 'invalid', evidence: { status: 401 } };
        if (r.status === 403) return { status: 'expired', evidence: { status: 403, note: 'forbidden/rate limit' } };
        return { status: 'unknown', evidence: { status: r.status } };
      }
      case 'stripe': {
        const r = await axios.get('https://api.stripe.com/v1/charges?limit=1', {
          headers: { Authorization: `Bearer ${secret}` },
          validateStatus: () => true, timeout: 8000,
        });
        if (r.status === 200) return { status: 'valid', evidence: { status: 200 } };
        if (r.status === 401) return { status: 'invalid', evidence: { status: 401 } };
        if (r.status === 403) return { status: 'expired', evidence: { status: 403 } };
        return { status: 'unknown', evidence: { status: r.status } };
      }
      case 'openai': {
        const r = await axios.get('https://api.openai.com/v1/models', {
          headers: { Authorization: `Bearer ${secret}` },
          validateStatus: () => true, timeout: 8000,
        });
        if (r.status === 200) return { status: 'valid', evidence: { status: 200 } };
        if (r.status === 401) return { status: 'invalid', evidence: { status: 401 } };
        if (r.status === 403) return { status: 'expired', evidence: { status: 403 } };
        return { status: 'unknown', evidence: { status: r.status } };
      }
      default:
        return { status: 'unknown', evidence: { note: 'no online validator for this provider' } };
    }
  } catch (e) {
    return { status: 'unknown', evidence: { note: (e.message || 'error').slice(0, 120) } };
  }
}

export const scanSecretKeys = async (req, res) => {
  const { code, validateOnline } = req.body || {};
  if (!code) return res.status(400).json({ error: 'Code is required for scanning.' });

  try {
    const lines = String(code).split('\n');
    const found = [];

    lines.forEach((lineText, index) => {
      rules.forEach((rule) => {
        const m = lineText.match(rule.regex);
        if (m) {
          const capture = m[1] || m[0]; // prefer group 1 if present
          found.push({
            type: rule.type,
            provider: rule.provider,
            line: index + 1,
            secret: capture,
            redacted: redact(capture),
            severity: rule.severity,
            suggestion: rule.suggestion,
          });
        }
      });
    });

    // dedupe
    const seen = new Set();
    const deduped = found.filter((s) => {
      const k = `${s.provider}:${s.secret}`;
      if (seen.has(k)) return false; seen.add(k); return true;
    });

    // Online validation (opt-in)
    if (validateOnline) {
      await Promise.all(deduped.map(async (item) => {
        item.validation = await validateKeyOnline(item.provider, item.secret);
      }));
    } else {
      deduped.forEach((item) => { item.validation = { status: 'unknown', evidence: { note: 'online validation not requested' } }; });
    }

    // Prepare redacted payload for response & DB
    const safeResults = deduped.map(({ secret, ...rest }) => rest);

    // --- Non-blocking DB save (never fail the request on DB error) ---
    const codeHash = crypto.createHash('sha256').update(code).digest('hex');
    const docToSaveA = { codeHash, codeLength: String(code).length, results: safeResults, createdAt: new Date() };
    const docToSaveB = { code: '(redacted)', results: safeResults, createdAt: new Date() }; // for schemas requiring `code`

    try {
      // Try preferred (no raw code)
      await SecretScan.create(docToSaveA);
    } catch (e1) {
      // Fallback for schemas that require `code`
      try {
        await SecretScan.create(docToSaveB);
      } catch (e2) {
        console.warn('SecretScan save failed (both modes). Continuing. Err:', e2.message);
      }
    }
    // ---------------------------------------------------------------

    return res.status(200).json({ secrets: safeResults });
  } catch (err) {
    console.error('Secret scan error:', err);
    // If anything unexpected happens, still return a friendly error
    return res.status(500).json({ error: 'Failed to scan secrets.', details: err.message || String(err) });
  }
};
