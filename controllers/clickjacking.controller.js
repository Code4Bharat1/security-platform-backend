// controllers/clickjacking.controller.js
import ClickjackingTest from '../models/clickjacking.model.js';
import axios from 'axios';

/* ----------------------------- helpers ----------------------------- */

const UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
  '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

const normalizeUrl = (raw) => {
  if (!raw) return null;
  const s = String(raw).trim();
  return /^https?:\/\//i.test(s) ? s : `https://${s}`;
};

const withWWW = (u) => {
  try {
    const x = new URL(u);
    if (!x.hostname.startsWith('www.')) x.hostname = `www.${x.hostname}`;
    if (!x.pathname) x.pathname = '/';
    return x.toString();
  } catch {
    return u;
  }
};

const lowerHeaders = (h = {}) =>
  Object.fromEntries(Object.entries(h).map(([k, v]) => [String(k).toLowerCase(), v]));

/* -------------------------- CSP parsing ---------------------------- */

const parseCsp = (cspHeader = '') => {
  // normalize; handle multiple CSP headers or comma-joined values
  const joined = Array.isArray(cspHeader) ? cspHeader.join('; ') : String(cspHeader || '');
  const parts = joined.split(';').map((s) => s.trim().toLowerCase());
  const fa = parts.find((p) => p.startsWith('frame-ancestors'));
  if (!fa) return { hasFrameAncestors: false, frameAncestorsValue: null, allowsBroad: false };

  const value = fa.replace(/^frame-ancestors\s*/, '').trim(); // everything after the directive
  // “*”, “http:”, “https:”, or many domains => treat as broad (medium)
  const allowsBroad = value === '*' || /\bhttps?:\b/.test(value) || value.split(/\s+/).length > 3;
  return { hasFrameAncestors: true, frameAncestorsValue: value, allowsBroad };
};

/* ---------------------- Result computation ------------------------- */

const computeResult = (xfoRaw, cspRaw) => {
  const xfo = (Array.isArray(xfoRaw) ? xfoRaw[0] : xfoRaw)?.toUpperCase?.() || null;
  const hasXfo = !!xfo;
  const xfoIsStrong = hasXfo && (xfo.includes('SAMEORIGIN') || xfo.includes('DENY'));

  const { hasFrameAncestors, frameAncestorsValue, allowsBroad } = parseCsp(cspRaw);

  // Protection flags
  const protections = [];
  if (hasXfo) protections.push(`X-Frame-Options: ${xfo}`);
  if (hasFrameAncestors) protections.push(`Content-Security-Policy: frame-ancestors ${frameAncestorsValue}`);

  // Severity
  let severity = 'High';
  if (hasFrameAncestors && xfoIsStrong) severity = 'Safe';
  else if (hasFrameAncestors || xfoIsStrong) severity = allowsBroad ? 'Medium' : 'Medium';
  else severity = 'High';

  // Smart recommendations
  const recommendations = [];
  if (!hasXfo) {
    recommendations.push({
      id: 'add-xfo',
      priority: 'high',
      title: 'Implement Basic Protection',
      snippet: 'X-Frame-Options: SAMEORIGIN',
      explain: 'Blocks all cross-origin framing in legacy and modern browsers.',
    });
  } else if (!xfoIsStrong) {
    recommendations.push({
      id: 'tighten-xfo',
      priority: 'medium',
      title: 'Tighten X-Frame-Options',
      snippet: 'X-Frame-Options: SAMEORIGIN',
      explain: `Current value "${xfo}" is not strict enough.`,
    });
  }

  if (!hasFrameAncestors) {
    recommendations.push({
      id: 'add-csp-fa',
      priority: 'high',
      title: 'Implement CSP Protection',
      snippet: "Content-Security-Policy: frame-ancestors 'self'",
      explain: 'Modern, robust control over who can frame your site.',
    });
  } else if (allowsBroad) {
    recommendations.push({
      id: 'tighten-csp-fa',
      priority: 'medium',
      title: 'Tighten CSP frame-ancestors',
      snippet: "Content-Security-Policy: frame-ancestors 'self'",
      explain: `Current policy (${frameAncestorsValue}) allows broad framing.`,
    });
  }

  // Optional JS frame-busting suggestion (defense-in-depth)
  if (!hasFrameAncestors || !xfoIsStrong) {
    recommendations.push({
      id: 'js-framebust',
      priority: 'low',
      title: 'Additional JavaScript Protection (Optional)',
      snippet: `if (window.top !== window.self) {\n  window.top.location = window.self.location;\n}`,
      explain: 'Adds a defense-in-depth layer, but do not rely on it alone.',
    });
  }

  // “Iframe loading test” inferred: blocked if strong XFO or CSP FA present
  const iframeBlocked = Boolean(xfoIsStrong || hasFrameAncestors);

  return {
    isProtected: protections.length > 0,
    protectedBy: protections,
    severity,
    headers: {
      xFrameOptions: xfo || null,
      csp: Array.isArray(cspRaw) ? cspRaw.join(', ') : cspRaw || null,
      hasXfo: hasXfo,
      hasCspFrameAncestors: hasFrameAncestors,
    },
    iframeBlocked,
    recommendations,
  };
};

/* --------------------------- Main handler -------------------------- */

export const testClickjacking = async (req, res) => {
  // accept both url/targetUrl to avoid payload key mismatch between envs
  let raw = req.body?.url || req.body?.targetUrl;
  if (!raw) return res.status(400).json({ error: 'URL is required' });

  let url = normalizeUrl(raw);
  try {
    new URL(url);
  } catch {
    return res.status(422).json({ error: 'Invalid URL format' });
  }

  const axiosOpts = (target) => ({
    method: 'GET', // ← never HEAD; many sites 405/403 on HEAD
    url: target,
    maxRedirects: 10,
    timeout: 10000,
    validateStatus: () => true,
    headers: {
      'User-Agent': UA,
      Accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8',
    },
  });

  try {
    // 1) primary GET
    let resp = await axios(axiosOpts(url));

    // 2) Retry once for common blocks with www + '/'
    if ([405, 403].includes(resp.status)) {
      const alt = withWWW(url);
      if (alt !== url) {
        url = alt;
        resp = await axios(axiosOpts(url));
      }
    }

    // final URL after redirects
    const finalUrl =
      resp.request?.res?.responseUrl ||
      resp.request?._currentUrl ||
      url;

    const headers = lowerHeaders(resp.headers);
    const xfo = headers['x-frame-options'] || null;
    const csp = headers['content-security-policy'] || null;

    // If upstream failed, return diagnostics but keep HTTP 200 so UI can render a "Failed" card
    if (resp.status >= 400) {
      return res.status(200).json({
        ok: false,
        url: finalUrl,
        upstreamStatus: resp.status,
        reason: 'UPSTREAM_HTTP_ERROR',
        message: `Upstream responded ${resp.status}`,
      });
    }

    // Analyze protections
    const { isProtected, protectedBy, severity, headers: hdrOut, iframeBlocked, recommendations } =
      computeResult(xfo, csp);

    // Save (non-blocking; don’t fail user if DB write errors)
    try {
      await new ClickjackingTest({
        url: finalUrl,
        isProtected,
        protectedBy,
        severity,
        upstreamStatus: resp.status,
        checkedAt: new Date(),
      }).save();
    } catch (_) {}

    // Success
    return res.status(200).json({
      ok: true,
      url: finalUrl,
      isProtected,
      protectedBy,
      severity,
      headers: hdrOut,
      iframeBlocked,
      recommendations,
      upstreamStatus: resp.status,
    });
  } catch (err) {
    console.error('Clickjacking test error:', err?.message || err);
    return res.status(200).json({
      ok: false,
      reason: 'NETWORK_OR_EXCEPTION',
      message: err?.message || String(err),
    });
  }
};
