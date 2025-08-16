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

// classify network errors that mean “invalid/unreachable link”
const INVALID_LINK_CODES = new Set([
  'ENOTFOUND', 'EAI_AGAIN', 'ERR_INVALID_URL', 'ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT',
  'HPE_INVALID_URL'
]);
const isInvalidLinkError = (e) =>
  INVALID_LINK_CODES.has(e?.code) || INVALID_LINK_CODES.has(e?.cause?.code);

/* -------------------------- CSP parsing ---------------------------- */

const parseCsp = (cspHeader = '') => {
  const joined = Array.isArray(cspHeader) ? cspHeader.join('; ') : String(cspHeader || '');
  const parts = joined.split(';').map((s) => s.trim().toLowerCase());
  const fa = parts.find((p) => p.startsWith('frame-ancestors'));
  if (!fa) return { hasFrameAncestors: false, frameAncestorsValue: null, allowsBroad: false };

  const value = fa.replace(/^frame-ancestors\s*/, '').trim();
  const allowsBroad = value === '*' || /\bhttps?:\b/.test(value) || value.split(/\s+/).length > 3;
  return { hasFrameAncestors: true, frameAncestorsValue: value, allowsBroad };
};

/* ---------------------- Result computation ------------------------- */

const computeResult = (xfoRaw, cspRaw) => {
  const xfo = (Array.isArray(xfoRaw) ? xfoRaw[0] : xfoRaw)?.toUpperCase?.() || null;
  const hasXfo = !!xfo;
  const xfoIsStrong = hasXfo && (xfo.includes('SAMEORIGIN') || xfo.includes('DENY'));

  const { hasFrameAncestors, frameAncestorsValue, allowsBroad } = parseCsp(cspRaw);

  const protections = [];
  if (hasXfo) protections.push(`X-Frame-Options: ${xfo}`);
  if (hasFrameAncestors) protections.push(`Content-Security-Policy: frame-ancestors ${frameAncestorsValue}`);

  let severity = 'High';
  if (hasFrameAncestors && xfoIsStrong) severity = 'Safe';
  else if (hasFrameAncestors || xfoIsStrong) severity = 'Medium';

  const recommendations = [];
  if (!hasXfo) {
    recommendations.push({
      id: 'add-xfo', priority: 'high',
      title: 'Implement Basic Protection',
      snippet: 'X-Frame-Options: SAMEORIGIN',
      explain: 'Blocks all cross-origin framing in legacy and modern browsers.',
    });
  } else if (!xfoIsStrong) {
    recommendations.push({
      id: 'tighten-xfo', priority: 'medium',
      title: 'Tighten X-Frame-Options',
      snippet: 'X-Frame-Options: SAMEORIGIN',
      explain: `Current value "${xfo}" is not strict enough.`,
    });
  }

  if (!hasFrameAncestors) {
    recommendations.push({
      id: 'add-csp-fa', priority: 'high',
      title: 'Implement CSP Protection',
      snippet: "Content-Security-Policy: frame-ancestors 'self'",
      explain: 'Modern, robust control over who can frame your site.',
    });
  } else if (allowsBroad) {
    recommendations.push({
      id: 'tighten-csp-fa', priority: 'medium',
      title: 'Tighten CSP frame-ancestors',
      snippet: "Content-Security-Policy: frame-ancestors 'self'",
      explain: `Current policy (${frameAncestorsValue}) allows broad framing.`,
    });
  }

  if (!hasFrameAncestors || !xfoIsStrong) {
    recommendations.push({
      id: 'js-framebust', priority: 'low',
      title: 'Additional JavaScript Protection (Optional)',
      snippet: `if (window.top !== window.self) {\n  window.top.location = window.self.location;\n}`,
      explain: 'Adds a defense-in-depth layer, but do not rely on it alone.',
    });
  }

  const iframeBlocked = Boolean(xfoIsStrong || hasFrameAncestors);

  return {
    isProtected: protections.length > 0,
    protectedBy: protections,
    severity,
    headers: {
      xFrameOptions: xfo || null,
      csp: Array.isArray(cspRaw) ? cspRaw.join(', ') : cspRaw || null,
      hasXfo, hasCspFrameAncestors: hasFrameAncestors,
    },
    iframeBlocked,
    recommendations,
  };
};

/* --------------------------- Main handler -------------------------- */

export const testClickjacking = async (req, res) => {
  let raw = req.body?.url || req.body?.targetUrl;
  if (!raw) return res.status(400).json({ ok:false, reason:'INVALID_LINK', error: 'URL is required' });

  let url = normalizeUrl(raw);
  try { new URL(url); } catch {
    return res.status(422).json({ ok:false, reason:'INVALID_LINK', error: 'Invalid URL format' });
  }

  const axiosOpts = (target) => ({
    method: 'GET',
    url: target,
    maxRedirects: 10,
    timeout: 40000,
    validateStatus: () => true,
    headers: { 'User-Agent': UA, Accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8' },
  });

  try {
    let resp = await axios(axiosOpts(url));

    // Retry once if blocked by policy on HEAD/UA/host shape
    if ([405, 403].includes(resp.status)) {
      const alt = withWWW(url);
      if (alt !== url) {
        url = alt;
        resp = await axios(axiosOpts(url));
      }
    }

    const finalUrl =
      resp.request?.res?.responseUrl ||
      resp.request?._currentUrl ||
      url;

    const headers = lowerHeaders(resp.headers);
    const xfo = headers['x-frame-options'] || null;
    const csp = headers['content-security-policy'] || null;

    // Treat "not found" statuses as INVALID_LINK
    if (new Set([404, 410, 451]).has(resp.status)) {
      return res.status(200).json({
        ok: false,
        reason: 'INVALID_LINK',
        url: finalUrl,
        upstreamStatus: resp.status,
        message: 'Invalid link or page not found.',
      });
    }

    // Other upstream errors → diagnostic
    if (resp.status >= 400) {
      return res.status(200).json({
        ok: false,
        reason: 'UPSTREAM_HTTP_ERROR',
        url: finalUrl,
        upstreamStatus: resp.status,
        message: `Upstream responded ${resp.status}`,
      });
    }

    const { isProtected, protectedBy, severity, headers: hdrOut, iframeBlocked, recommendations } =
      computeResult(xfo, csp);

    // Non-blocking save
    try {
      await new ClickjackingTest({
        url: finalUrl, isProtected, protectedBy, severity,
        upstreamStatus: resp.status, checkedAt: new Date(),
      }).save();
    } catch {}

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
    // Network/DNS/etc. → INVALID_LINK
    if (isInvalidLinkError(err)) {
      return res.status(200).json({
        ok: false,
        reason: 'INVALID_LINK',
        message: 'Invalid link or host not found.',
        errorCode: err.code || err?.cause?.code || 'UNKNOWN',
      });
    }
    console.error('Clickjacking test error:', err?.message || err);
    return res.status(200).json({
      ok: false,
      reason: 'NETWORK_OR_EXCEPTION',
      message: err?.message || String(err),
    });
  }
};
