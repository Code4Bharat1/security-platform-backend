import CsrfReport from '../models/CsrfReport.js';
import { parse } from 'node-html-parser';

const PLACEHOLDER_PATTERNS = [/{{.*?}}/, /<%=?\s*.*?\s*%>/, /{%\s*.*?\s*%}/, /value=\{.*?\}/i];
const TOKEN_INPUT_SELECTOR = 'input[name="_csrf"], input[name="csrf_token"], input[name="_token"], input[name="csrf"], input[name="csrfToken"]';
const META_TOKEN_SELECTOR  = 'meta[name="csrf-token"], meta[name="_csrf"], meta[name="csrf_token"], meta[name="x-csrf-token"]';

function isPlaceholder(val = '') {
  return PLACEHOLDER_PATTERNS.some((re) => re.test(val));
}

function shannonEntropy(str = '') {
  if (!str || typeof str !== 'string') return 0;
  const len = str.length;
  if (!len) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let H = 0;
  for (const k in freq) {
    const p = freq[k] / len;
    H -= p * Math.log2(p);
  }
  return H;
}

function looksStrongRandom(token = '') {
  const len = token.length;
  const entropy = shannonEntropy(token);
  const hasMix = /[a-z]/.test(token) && /[A-Z]/.test(token) && /\d/.test(token);
  const isBase64ish = /^[A-Za-z0-9+/=]{24,}$/.test(token);
  const isHexLong = /^[a-f0-9]{32,}$/i.test(token);
  // Heuristic: long + high-ish entropy OR common token encodings
  return (len >= 16 && entropy >= 3.5 && (hasMix || /\W/.test(token))) || isBase64ish || isHexLong;
}

export const analyzeCSRF = async (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: 'Code is required' });

  const issues = [];
  let vulnerable = false;

  // ---- findings for scoring ----
  let tokenPresentOK = false;        // +30
  let cookieSameSiteOK = false;      // +30
  let originRefererOK = false;       // +30
  let tokenRandomnessOK = false;     // +10

  try {
    const root = parse(code);
    const codeLower = code.toLowerCase();

    // ---------- 1) Token presence & “static vs dynamic” ----------
    const tokenCandidates = [];

    // 1a) Look at forms (hidden token inputs)
    const forms = root.querySelectorAll('form');
    let formWithoutToken = false;
    for (const form of forms) {
      const tok = form.querySelector(TOKEN_INPUT_SELECTOR);
      if (!tok) {
        formWithoutToken = true;
      } else {
        tokenPresentOK = true;
        const val = tok.getAttribute('value') || '';
        const literal = !!val && !isPlaceholder(val);
        tokenCandidates.push({ source: 'input', value: val, literal, placeholder: isPlaceholder(val) });
      }
    }
    if (forms.length > 0 && formWithoutToken) {
      issues.push('Form element detected without CSRF token.');
      vulnerable = true;
    }

    // 1b) Meta tags
    root.querySelectorAll(META_TOKEN_SELECTOR).forEach((m) => {
      tokenPresentOK = true;
      const val = m.getAttribute('content') || '';
      tokenCandidates.push({ source: 'meta', value: val, literal: !!val && !isPlaceholder(val), placeholder: isPlaceholder(val) });
    });

    // 1c) JS literals (e.g., const csrfToken = 'abc...')
    const jsLiteralMatches = [...code.matchAll(/\b(const|let|var)\s+(?:_?csrf|csrfToken|csrf_token)\s*=\s*['"]([^'"]+)['"]/gi)];
    jsLiteralMatches.forEach((m) => {
      tokenPresentOK = true;
      tokenCandidates.push({ source: 'js', value: m[2], literal: true, placeholder: false });
    });

    // 1d) Token header usage (X-CSRF-Token header)
    if (/\b['"]x-?csrf-?token['"]\s*:\s*['"][^'"]+['"]/i.test(code)) {
      tokenPresentOK = true;
      const headerVal = (code.match(/\b['"]x-?csrf-?token['"]\s*:\s*['"]([^'"]+)['"]/i) || [])[1] || '';
      tokenCandidates.push({ source: 'header', value: headerVal, literal: !!headerVal && !isPlaceholder(headerVal), placeholder: isPlaceholder(headerVal) });
    }

    // Static token heuristic:
    // - any candidate with a hard-coded literal value and NOT a known template placeholder
    // - OR obvious hard-coded strings in headers
    const hardcoded = tokenCandidates.filter(t => t.literal && !t.placeholder && t.value);
    if (hardcoded.length) {
      vulnerable = true;
      issues.push('CSRF token appears hard-coded/static. Tokens should be per-session or per-request.');
    }

    // Token randomness check (grant if any candidate looks strong OR is non-literal/templated)
    if (tokenCandidates.length) {
      tokenRandomnessOK = tokenCandidates.some(t => !t.literal || looksStrongRandom(t.value));
      if (!tokenRandomnessOK) {
        issues.push('CSRF token lacks apparent randomness/entropy.');
        vulnerable = true;
      }
    }

    // ---------- 2) Fetch/XMLHttpRequest hygiene ----------
    // Your original checks kept (with improvements)

    // 2a) fetch POSTs: require credentials: 'include' or 'same-origin'
    const fetchPosts = [...codeLower.matchAll(/fetch\(\s*[^)]*?\)/g)];
    let anyFetchPost = false;
    fetchPosts.forEach((m) => {
      const snippet = m[0];
      const methodPost = /method\s*:\s*['"]post['"]/.test(snippet);
      if (methodPost) {
        anyFetchPost = true;
        const hasCreds = /credentials\s*:\s*['"](include|same-origin)['"]/.test(snippet);
        if (!hasCreds) {
          issues.push('Potential unsafe fetch POST without credentials included.');
          vulnerable = true;
        }
        // Origin/Referrer: check referrerPolicy or same-origin enforcement
        const hasRefPol = /referrerpolicy\s*:\s*['"](same-origin|strict-origin|strict-origin-when-cross-origin)['"]/i.test(snippet);
        const relativeUrl = /fetch\(\s*['"]\//.test(snippet); // naive same-origin hint
        if (hasRefPol || relativeUrl) originRefererOK = true;
      }
    });

    // 2b) XMLHttpRequest: withCredentials
    if (codeLower.includes('xmlhttprequest')) {
      const usesWithCreds = /withcredentials\s*=\s*true/i.test(codeLower);
      if (!usesWithCreds) {
        issues.push('Potential unsafe XMLHttpRequest POST without credentials included.');
        vulnerable = true;
      } else {
        originRefererOK = true; // withCredentials implies same-site cookies will be sent
      }
    }

    // If we saw cross-site capable requests but no sign of referrer/origin policy:
    if ((anyFetchPost || codeLower.includes('xmlhttprequest')) && !originRefererOK) {
      issues.push('No explicit referrer/origin policy detected for state-changing requests.');
      // not necessarily mark vulnerable alone, but we’ll keep it as a warning
    }

    // ---------- 3) Cookie SameSite ----------
    // Award only if we detect Set-Cookie (e.g., server headers in docs) WITH SameSite
    const mentionsSetCookie = /set-cookie/i.test(codeLower);
    const mentionsSameSite = /samesite\s*=\s*(lax|strict|none)/i.test(codeLower);
    if (mentionsSetCookie && mentionsSameSite) {
      cookieSameSiteOK = true;
    } else if (mentionsSetCookie && !mentionsSameSite) {
      issues.push('Cookie usage without SameSite attribute detected.');
      vulnerable = true;
    }
    // Note: JS cannot set SameSite via document.cookie; this must be server-side.

  } catch (err) {
    return res.status(400).json({ error: 'Invalid HTML or code format' });
  }

  // ---------- Scoring ----------
  // Token ✅ = +30
  // Cookie check ✅ = +30
  // Origin/Referer ✅ = +30
  // Token randomness ✅ = +10
  let score = 0;
  if (tokenPresentOK)    score += 30;
  if (cookieSameSiteOK)  score += 30;
  if (originRefererOK)   score += 30;
  if (tokenRandomnessOK) score += 10;

  let riskLevel = 'Low';
  if (score < 50) riskLevel = 'High';
  else if (score < 80) riskLevel = 'Medium';

  // Save report (extended)
  const report = new CsrfReport({
    code,
    vulnerable,
    issues,
    score,
    riskLevel,
    breakdown: {
      tokenPresentOK,
      cookieSameSiteOK,
      originRefererOK,
      tokenRandomnessOK
    }
  });
  await report.save();

  return res.status(200).json({
    vulnerable,
    issues,
    score,
    riskLevel,
    breakdown: {
      tokenPresentOK,
      cookieSameSiteOK,
      originRefererOK,
      tokenRandomnessOK
    }
  });
};
