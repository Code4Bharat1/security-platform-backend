// controllers/scanController.js
import sslChecker from 'ssl-checker';
import axios from 'axios';
import https from 'https';
import ScanResult from '../models/scanResultModel.js';

/* ========== Helpers (kept inside same controller file) ========== */

function parseSetCookie(setCookieHeader) {
  const list = Array.isArray(setCookieHeader)
    ? setCookieHeader
    : setCookieHeader
    ? [setCookieHeader]
    : [];

  const findings = [];
  for (const raw of list) {
    const parts = raw.split(';').map((p) => p.trim());
    const [nameValue, ...attrs] = parts;
    const [name] = nameValue.split('=');

    const flags = [];
    const issues = [];

    const hasSecure   = attrs.some((a) => /^secure$/i.test(a));
    const hasHttpOnly = attrs.some((a) => /^httponly$/i.test(a));
    const sameSite    = attrs.find((a) => /^samesite=/i.test(a));
    const hasDomain   = attrs.find((a) => /^domain=/i.test(a));
    const hasPath     = attrs.find((a) => /^path=/i.test(a));

    if (!hasSecure) issues.push('Missing Secure');
    if (!hasHttpOnly) issues.push('Missing HttpOnly');
    if (!sameSite) issues.push('Missing SameSite');

    if (hasSecure) flags.push('Secure');
    if (hasHttpOnly) flags.push('HttpOnly');
    if (sameSite) flags.push(sameSite);
    if (hasDomain) flags.push(hasDomain);
    if (hasPath) flags.push(hasPath);

    findings.push({ name, flags, issues });
  }
  return findings;
}

function analyzeCSP(csp) {
  if (!csp) {
    return {
      present: false,
      policy: '',
      issues: ['Missing Content-Security-Policy header'],
      directives: {}
    };
  }
  const issues = [];
  const directives = {};
  csp
    .split(';')
    .map((s) => s.trim())
    .filter(Boolean)
    .forEach((dir) => {
      const [k, ...vals] = dir.split(/\s+/);
      directives[k] = vals;
    });

  if (!directives['default-src']) issues.push('Missing default-src');

  // Risky tokens
  ['script-src', 'style-src'].forEach((k) => {
    const v = directives[k] || [];
    if (v.includes(`'unsafe-inline'`)) issues.push(`${k} contains 'unsafe-inline'`);
    if (v.includes(`'unsafe-eval'`)) issues.push(`${k} contains 'unsafe-eval'`);
  });

  if (!directives['frame-ancestors']) {
    issues.push('Missing frame-ancestors (clickjacking risk)');
  }

  if (!('upgrade-insecure-requests' in directives)) {
    issues.push('Missing upgrade-insecure-requests');
  }

  Object.entries(directives).forEach(([k, vals]) => {
    if (vals?.includes('*')) issues.push(`${k} allows *`);
  });

  return { present: true, policy: csp, issues, directives };
}

function countMissingSecurityHeaders(headers = {}) {
  const needed = [
    'strict-transport-security',
    'content-security-policy',
    'x-content-type-options',
    'x-frame-options',
    'x-xss-protection'
  ];
  return needed.filter((h) => !headers[h]).length;
}

function gradeFromMetrics({ vulnCount, missingSecHeaders, weakCookies, cspIssues }) {
  const score =
    100 -
    Math.min(vulnCount * 8, 40) -
    Math.min(missingSecHeaders * 8, 40) -
    Math.min(weakCookies * 4, 12) -
    Math.min(cspIssues * 5, 25);

  return score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 65 ? 'C' : 'D';
}

/* ========== MAIN: Run Scan (POST /scan/run-scan) ========== */

export const runScan = async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required.' });

  try {
    const domain = url.replace(/^https?:\/\//, '').split('/')[0];
    const formattedUrl = `https://${domain}`;

    const scanResults = {
      domain,
      timestamp: new Date().toISOString(),
      ssl: null,
      headers: null,
      openPorts: null,
      vulnerabilities: [],
      vulnerabilityCount: 0,
      riskLevel: 'low',
      timespan: 0, // ms for main request
    };

    // 1) SSL
    try {
      scanResults.ssl = await sslChecker(domain);
    } catch (error) {
      scanResults.vulnerabilities.push({
        type: 'ssl',
        severity: 'high',
        description: 'SSL certificate issue detected',
        details: error.message,
        recommendation: 'Fix certificate chain/expiration/hostname mismatch'
      });
    }

    // 2) HTTP headers (with raw + metrics)
    try {
      const agent = new https.Agent({ rejectUnauthorized: false });
      const started = Date.now();
      const response = await axios.get(formattedUrl, {
        timeout: 8000,
        httpsAgent: agent,
        validateStatus: () => true,
        maxRedirects: 0
      });
      scanResults.timespan = Date.now() - started;

      const headers = response.headers || {};
      // Base headers store
      scanResults.headers = headers;

      // Raw server headers and status details (store inside headers.* to fit your model)
      const nodeRes = response?.request?.res;
      if (nodeRes) {
        scanResults.headers.rawHeaders = nodeRes.rawHeaders || [];
        scanResults.headers.httpVersion = nodeRes.httpVersion || '';
        scanResults.headers.statusCode = nodeRes.statusCode;
        scanResults.headers.statusMessage = nodeRes.statusMessage || '';
      } else {
        // Fallback: flatten
        scanResults.headers.rawHeaders = Object.entries(headers).flatMap(([k, v]) => [
          k,
          Array.isArray(v) ? v.join(', ') : String(v)
        ]);
      }

      // Missing security headers → vulnerabilities
      const secHeaders = {
        'strict-transport-security': 'Strict Transport Security not configured',
        'content-security-policy': 'Content Security Policy not configured',
        'x-content-type-options': 'X-Content-Type-Options not configured',
        'x-frame-options': 'X-Frame-Options not configured',
        'x-xss-protection': 'X-XSS-Protection not configured'
      };
      for (const [h, message] of Object.entries(secHeaders)) {
        if (!headers[h]) {
          scanResults.vulnerabilities.push({
            type: 'header',
            severity: 'medium',
            description: message,
            details: `Missing header: ${h}`,
            recommendation: `Add the ${h} header`
          });
        }
      }

      // Info disclosure
      if (headers.server) {
        scanResults.vulnerabilities.push({
          type: 'information_disclosure',
          severity: 'low',
          description: 'Server information disclosure',
          details: `Server header reveals: ${headers.server}`,
          recommendation: 'Avoid exposing server brand/version'
        });
      }

      // Cookies audit
      const cookieFindings = parseSetCookie(headers['set-cookie']);
      scanResults.headers.cookies = cookieFindings;
      for (const c of cookieFindings) {
        if (c.issues.length) {
          scanResults.vulnerabilities.push({
            type: 'cookie',
            severity: 'medium',
            description: `Cookie "${c.name}" has weaknesses`,
            details: c.issues.join(', '),
            recommendation: 'Set Secure, HttpOnly, and SameSite'
          });
        }
      }

      // CSP analyzer
      const cspHeader = Array.isArray(headers['content-security-policy'])
        ? headers['content-security-policy'][0]
        : headers['content-security-policy'];
      const cspAnalysis = analyzeCSP(cspHeader);
      scanResults.headers.csp = cspAnalysis;

      if (!cspAnalysis.present || cspAnalysis.issues.length) {
        scanResults.vulnerabilities.push({
          type: 'csp',
          severity: cspAnalysis.present ? 'medium' : 'high',
          description: cspAnalysis.present ? 'CSP has issues' : 'CSP missing',
          details: cspAnalysis.issues.join('; '),
          recommendation:
            'Harden CSP (add default-src, remove unsafe-* tokens, set frame-ancestors, add upgrade-insecure-requests)'
        });
      }
    } catch (error) {
      scanResults.vulnerabilities.push({
        type: 'connection',
        severity: 'medium',
        description: 'Failed to connect or retrieve headers',
        details: error.message,
        recommendation: 'Ensure HTTPS is reachable and not blocking scanners'
      });
    }

    // 3) Sensitive path checks
    const commonPaths = [
      '/.git/config',
      '/.env',
      '/wp-config.php',
      '/phpinfo.php',
      '/admin',
      '/config',
      '/backup',
      '/wp-admin',
      '/server-status'
    ];
    const agent2 = new https.Agent({ rejectUnauthorized: false });
    await Promise.all(
      commonPaths.map(async (path) => {
        try {
          const r = await axios.get(`https://${domain}${path}`, {
            timeout: 3000,
            httpsAgent: agent2,
            validateStatus: () => true,
            maxRedirects: 0
          });
          if (r.status === 200) {
            scanResults.vulnerabilities.push({
              type: 'exposure',
              severity: 'high',
              description: 'Potentially sensitive resource exposed',
              details: `${path} is accessible (Status: ${r.status})`,
              recommendation: 'Restrict access (403), remove from web root, or protect with auth'
            });
          }
        } catch {
          /* ignore */
        }
      })
    );

    // 4) Final tallies
    scanResults.vulnerabilityCount = scanResults.vulnerabilities.length;
    scanResults.riskLevel =
      scanResults.vulnerabilityCount > 5 ? 'high' :
      scanResults.vulnerabilityCount > 2 ? 'medium' : 'low';

    // 5) Benchmark vs last 10 scans for same domain (stored under headers._benchmark)
    const SAMPLE_N = 10;
    const prevScans = await ScanResult.find({ domain }).sort({ timestamp: -1 }).limit(SAMPLE_N);
    if (prevScans.length) {
      const missingNow = countMissingSecurityHeaders(scanResults.headers || {});
      const weakCookiesNow = (scanResults.headers?.cookies || []).filter((c) => c.issues.length).length;
      const cspIssuesNow = scanResults.headers?.csp?.issues?.length || 0;

      const avg = (arr) => (arr.length ? arr.reduce((a, b) => a + b, 0) / arr.length : 0);

      const prevMissing = avg(prevScans.map((s) => countMissingSecurityHeaders(s.headers || {})));
      const prevWeakCookies = avg(
        prevScans.map((s) => (s.headers?.cookies || []).filter((c) => c.issues?.length).length)
      );
      const prevCspIssues = avg(prevScans.map((s) => s.headers?.csp?.issues?.length || 0));
      const prevVulnCount = avg(prevScans.map((s) => s.vulnerabilityCount || 0));

      scanResults.headers = scanResults.headers || {};
      scanResults.headers._benchmark = {
        comparedTo: prevScans.length,
        deltas: {
          vulnCountDelta: Number((scanResults.vulnerabilityCount - prevVulnCount).toFixed(2)),
          missingSecHeadersDelta: Number((missingNow - prevMissing).toFixed(2)),
          weakCookiesDelta: Number((weakCookiesNow - prevWeakCookies).toFixed(2)),
          cspIssuesDelta: Number((cspIssuesNow - prevCspIssues).toFixed(2))
        },
        grade: gradeFromMetrics({
          vulnCount: scanResults.vulnerabilityCount,
          missingSecHeaders: missingNow,
          weakCookies: weakCookiesNow,
          cspIssues: cspIssuesNow
        })
      };
    }

    // 6) Persist and return
    const saved = await ScanResult.create(scanResults);
    return res.status(200).json(saved);
  } catch (error) {
    return res.status(500).json({
      error: 'Failed to complete vulnerability scan',
      message: error.message
    });
  }
};

/* ========== HISTORY (GET /scan/history?domain=...) — same controller file ========== */

export const getHistory = async (req, res) => {
  const { domain, limit = 10 } = req.query;
  if (!domain) return res.status(400).json({ error: 'domain is required' });

  const rows = await ScanResult.find({ domain })
    .select('domain timestamp vulnerabilityCount riskLevel timespan headers._benchmark.grade ssl.valid')
    .sort({ timestamp: -1 })
    .limit(Math.min(Number(limit) || 10, 50));

  res.json({ domain, count: rows.length, items: rows });
};
