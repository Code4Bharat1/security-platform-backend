import crypto from 'crypto';
import SessionFixationReport from '../models/sessionFixationReport.js';

// ----- helpers -----
const linesOf = (code) => code.replace(/\r\n/g, '\n').split('\n');
const cvssBy = (sev) => ({ Low: 3.1, Medium: 6.5, High: 8.1, Critical: 9.8 }[sev] || 0);
const clamp = (n, a, b) => Math.max(a, Math.min(b, n));

// FIX: robust locate() that accepts a RegExp or string and ensures global flag
const locate = (code, rx) => {
  const L = linesOf(code);
  const matches = [];
  let r;

  if (rx instanceof RegExp) {
    const flags = rx.flags.includes('g') ? rx.flags : rx.flags + 'g';
    r = new RegExp(rx.source, flags);
  } else {
    r = new RegExp(String(rx), 'g');
  }

  L.forEach((ln, i) => {
    r.lastIndex = 0; // reset for each line
    let m;
    while ((m = r.exec(ln)) !== null) {
      matches.push({
        line: i + 1,
        snippet: ln.trim().slice(0, 300),
        columnStart: m.index,
        columnEnd: m.index + ((m[0] && m[0].length) || 1),
      });
      if (!r.global) break; // safety: prevent infinite loops
    }
  });
  return matches;
};

const countBySeverity = (findings) => {
  const c = { critical: 0, high: 0, medium: 0, low: 0 };
  findings.forEach((f) => {
    const s = (f.severity || '').toLowerCase();
    if (s in c) c[s]++;
  });
  const overall = c.critical ? 'Critical' : c.high ? 'High' : c.medium ? 'Medium' : 'Low';
  return { ...c, totalFindings: findings.length, overallRisk: overall };
};

// ----- rules (regex-based heuristics; safe defaults) -----
function analyze(code) {
  const findings = [];
  const L = linesOf(code).length;

  // 1) Missing regenerate after auth
  const hasRegen = /req\.session\.regenerate\s*\(/.test(code);
  const hasLoginPattern = /(password.*(compare|check)|passport\.authenticate|jwt\.sign|user\.validate)/i.test(code);
  if (!hasRegen && hasLoginPattern) {
    findings.push({
      id: 'R1',
      rule: 'No session regeneration after login',
      severity: 'High',
      cvss: cvssBy('High'),
      exploitability: 'Easy',
      confidence: 'High',
      message: 'No session ID regeneration detected after authentication.',
      reasoning:
        'Without regeneration, an attacker who fixed/guessed a pre-login SID can keep using it post-login.',
      suggestion: 'Call req.session.regenerate(cb) immediately after successful login.',
      attackScenario:
        'Attacker forces victim to use known SID, victim logs in, attacker reuses same SID to hijack session.',
      locations: locate(code, /login|authenticate|password|jwt/i),
    });
  }

  // 2) Possible reuse of session id
  if (/req\.sessionID|req\.session\.id/.test(code)) {
    findings.push({
      id: 'R2',
      rule: 'Direct session id usage',
      severity: 'Medium',
      cvss: cvssBy('Medium'),
      exploitability: 'Moderate',
      confidence: 'Medium',
      message: 'Code references raw session ID; ensure it is never persisted/client-controlled.',
      reasoning: 'Leaking or persisting SIDs raises fixation/hijack risk.',
      suggestion: 'Avoid logging/persisting SIDs; rely on server session store only.',
      attackScenario: 'SID logged or sent to third-party, allowing reuse.',
      locations: locate(code, /req\.sessionID|req\.session\.id/),
    });
  }

  // 3) Cookie flags (Express-session style)
  const cookieBlock = code.match(/session\(\s*{[\s\S]*?cookie\s*:\s*{[\s\S]*?}\s*}[\s\S]*?}\s*\)/);
  const flags = { httpOnly: null, secure: null, sameSite: null, maxAgeMs: null };
  if (cookieBlock) {
    const s = cookieBlock[0];
    flags.httpOnly = /httpOnly\s*:\s*true/.test(s);
    flags.secure = /secure\s*:\s*true/.test(s);
    const sameSite = s.match(/sameSite\s*:\s*['"`]?(lax|strict|none)['"`]?/i);
    flags.sameSite = sameSite ? sameSite[1].toLowerCase() : null;
    const maxAge = s.match(/maxAge\s*:\s*(\d{3,})/);
    flags.maxAgeMs = maxAge ? clamp(parseInt(maxAge[1], 10), 0, 31_536_000_000) : null;

    if (flags.httpOnly !== true || flags.secure !== true || !flags.sameSite) {
      findings.push({
        id: 'R3',
        rule: 'Weak session cookie flags',
        severity: flags.secure === false || flags.sameSite === 'none' ? 'High' : 'Medium',
        cvss: cvssBy(flags.secure === false || flags.sameSite === 'none' ? 'High' : 'Medium'),
        exploitability: 'Easy',
        confidence: 'High',
        message: 'Cookie flags are missing or weak (HttpOnly/Secure/SameSite).',
        reasoning: 'Missing flags enable XSS/CSRF assisted session theft.',
        suggestion: 'Set HttpOnly:true, Secure:true, SameSite:"lax" (or "strict"), and a sensible maxAge.',
        attackScenario: 'Over HTTP or cross-site request leaks session cookie.',
        locations: locate(s, /cookie|httpOnly|secure|sameSite|maxAge/i),
      });
    }
  }

  // 4) Token entropy hints
  let entropyHint = null;
  if (/crypto\.randomBytes\(\s*3[2-9]\s*\)|uuid|nanoid/i.test(code)) entropyHint = 'Strong';
  else if (/Math\.random\(|Date\.now\(/.test(code)) {
    entropyHint = 'Weak';
    findings.push({
      id: 'R4',
      rule: 'Weak randomness for tokens',
      severity: 'High',
      cvss: cvssBy('High'),
      exploitability: 'Easy',
      confidence: 'Medium',
      message: 'Math.random/Date.now used for security tokens.',
      reasoning: 'Predictable tokens enable fixation/hijack.',
      suggestion: 'Use crypto.randomBytes(32) or a vetted library (uuid v4, nanoid).',
      attackScenario: 'Attacker predicts token sequence to take over session.',
      locations: locate(code, /Math\.random\(|Date\.now\(/),
    });
  }

  // 5) Binding, MFA, logout invalidation, priv-esc
  const ipBinding = /req\.ip|x-forwarded-for|session\.ip/i.test(code) && /if\s*\(.*ip/.test(code);
  const uaBinding = /user-agent/i.test(code) && /if\s*\(.*user.?agent/i.test(code);
  const mfaPresent = /otp|totp|2fa|mfa|speakeasy|authenticator/i.test(code);
  const logoutInvalidation = /session\.destroy\s*\(|logout\s*\(/i.test(code);
  const regenOnPrivEsc = /role|admin|scope|permission/i.test(code) && /session\.regenerate\s*\(/i.test(code);

  if (/http:\/\//.test(code)) {
    findings.push({
      id: 'R5',
      rule: 'Mixed content / insecure transport',
      severity: 'High',
      cvss: cvssBy('High'),
      exploitability: 'Easy',
      confidence: 'Low',
      message: 'HTTP usage detected; session must be over HTTPS only.',
      reasoning: 'Cookies with Secure flag are ignored on HTTP; interception possible.',
      suggestion: 'Force HTTPS, HSTS, and avoid absolute http:// URLs.',
      attackScenario: 'MITM steals cookie on plaintext request.',
      locations: locate(code, /http:\/\//),
    });
  }

  if (!logoutInvalidation) {
    findings.push({
      id: 'R6',
      rule: 'No server-side logout invalidation',
      severity: 'Medium',
      cvss: cvssBy('Medium'),
      exploitability: 'Moderate',
      confidence: 'Medium',
      message: 'Did not see session.destroy() during logout.',
      reasoning: 'Client-only logout keeps session alive.',
      suggestion: 'Call req.session.destroy() and rotate cookies on logout.',
      attackScenario: 'Old session remains valid and reused.',
      locations: locate(code, /logout|signout/i),
    });
  }

  const metrics = {
    cookieFlags: flags,
    sessionExpiry: flags.maxAgeMs ?? null,
    inactivityTimeoutHint: /rolling\s*:\s*true/.test(code)
      ? 'rolling: true'
      : /rolling\s*:\s*false/.test(code)
      ? 'rolling: false'
      : null,
    tokenEntropyHint: entropyHint,
    tokenReuseRisk: hasRegen ? 'Lower' : 'Higher',
    ipBinding,
    uaBinding,
    mfaPresent,
    mixedContent: /http:\/\//.test(code) || null,
    logoutInvalidation,
    regenOnPrivEsc,
  };

  // De-duplicate by rule+location line
  const key = (f) => `${f.rule}#${(f.locations?.[0]?.line) || 0}`;
  const dedup = Object.values(Object.fromEntries(findings.map((f) => [key(f), f])));

  return { findings: dedup, metrics, lines: L };
}

// ----- main endpoints -----
export const analyzeSessionFixation = async (req, res) => {
  try {
    const { code } = req.body;
    if (!code || !code.trim()) return res.status(400).json({ error: 'Code is required for analysis' });

    const { findings, metrics } = analyze(code);
    const counts = countBySeverity(findings);
    const codeHash = crypto.createHash('sha256').update(code, 'utf8').digest('hex');

    // historical comparison (same hash)
    const prev = await SessionFixationReport.findOne({ codeHash }).sort({ createdAt: -1 }).lean();

    // FIX: include `code` to satisfy schema's required constraint
    const reportDoc = await SessionFixationReport.create({
      code,                        // <--- added
      codeHash,
      codeLength: code.length,
      summary: counts,
      findings,
      metrics,
      comparison: prev
        ? {
            previousReportId: String(prev._id),
            deltaFindings: findings.length - (prev.summary?.totalFindings || 0),
          }
        : undefined,
    });

    // return rich payload + reportId
    return res.json({
      reportId: String(reportDoc._id),
      summary: reportDoc.summary,
      metrics: reportDoc.metrics,
      comparison: reportDoc.comparison || null,
      report: reportDoc.findings,
    });
  } catch (e) {
    console.error('Error analyzing session fixation:', e);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

// Export (JSON/CSV) by report id
export const exportSessionFixation = async (req, res) => {
  try {
    const { id } = req.params;
    const { format = 'json' } = req.query;
    const doc = await SessionFixationReport.findById(id).lean();
    if (!doc) return res.status(404).json({ error: 'Report not found' });

    if (format === 'json') {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', 'attachment; filename="session-fixation-report.json"');
      return res.send(JSON.stringify(doc, null, 2));
    }

    if (format === 'csv') {
      const headers = [
        'Severity',
        'Rule',
        'Message',
        'Confidence',
        'Exploitability',
        'CVSS',
        'Lines',
        'Suggestion',
        'Reasoning',
        'AttackScenario',
      ];
      const esc = (v = '') => `"${String(v).replace(/"/g, '""')}"`;
      const rows = (doc.findings || []).map((f) =>
        [
          f.severity || '',
          f.rule || '',
          f.message || '',
          f.confidence || '',
          f.exploitability || '',
          f.cvss ?? '',
          (f.locations || []).map((x) => x.line).join(';'),
          f.suggestion || '',
          f.reasoning || '',
          f.attackScenario || '',
        ]
          .map(esc)
          .join(',')
      );
      const csv = [headers.join(','), ...rows].join('\n');

      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="session-fixation-report.csv"');
      return res.send(csv);
    }

    return res.status(400).json({ error: 'Unsupported format. Use ?format=json|csv' });
  } catch (e) {
    console.error('Export error:', e);
    return res.status(500).json({ error: 'Internal server error' });
  }
};
