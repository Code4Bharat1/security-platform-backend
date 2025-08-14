// controllers/clickjacking.controller.js
import ClickjackingTest from '../models/clickjacking.model.js';
import axios from 'axios';
import { URL } from 'url';

const parseCsp = (cspHeader = '') => {
  // normalize; handle multiple CSP headers or comma-joined values
  const joined = Array.isArray(cspHeader) ? cspHeader.join('; ') : String(cspHeader || '');
  const parts = joined.split(';').map(s => s.trim().toLowerCase());
  const fa = parts.find(p => p.startsWith('frame-ancestors'));
  if (!fa) return { hasFrameAncestors: false, frameAncestorsValue: null, allowsBroad: false };

  const value = fa.replace(/^frame-ancestors\s*/,'').trim(); // everything after the directive
  // “*”, “http:”, “https:”, or many domains => treat as broad (medium)
  const allowsBroad = value === '*' || /\bhttps?:\b/.test(value) || value.split(/\s+/).length > 3;
  return { hasFrameAncestors: true, frameAncestorsValue: value, allowsBroad };
};

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
      explain: 'Blocks all cross-origin framing in legacy and modern browsers.'
    });
  } else if (!xfoIsStrong) {
    recommendations.push({
      id: 'tighten-xfo',
      priority: 'medium',
      title: 'Tighten X-Frame-Options',
      snippet: 'X-Frame-Options: SAMEORIGIN',
      explain: `Current value "${xfo}" is not strict enough.`
    });
  }

  if (!hasFrameAncestors) {
    recommendations.push({
      id: 'add-csp-fa',
      priority: 'high',
      title: 'Implement CSP Protection',
      snippet: "Content-Security-Policy: frame-ancestors 'self'",
      explain: 'Modern, robust control over who can frame your site.'
    });
  } else if (allowsBroad) {
    recommendations.push({
      id: 'tighten-csp-fa',
      priority: 'medium',
      title: 'Tighten CSP frame-ancestors',
      snippet: "Content-Security-Policy: frame-ancestors 'self'",
      explain: `Current policy (${frameAncestorsValue}) allows broad framing.`
    });
  }

  // Optional JS frame-busting suggestion (never a replacement)
  if (!hasFrameAncestors || !xfoIsStrong) {
    recommendations.push({
      id: 'js-framebust',
      priority: 'low',
      title: 'Additional JavaScript Protection (Optional)',
      snippet:
`if (window.top !== window.self) {
  window.top.location = window.self.location;
}`,
      explain: 'Adds a defense-in-depth layer, but do not rely on it alone.'
    });
  }

  // “Iframe loading test” is inferred: blocked if strong XFO or CSP FA present
  const iframeBlocked = Boolean(xfoIsStrong || hasFrameAncestors);

  return {
    isProtected: protections.length > 0,
    protectedBy: protections,
    severity,
    headers: {
      xFrameOptions: xfo || null,
      csp: Array.isArray(cspRaw) ? cspRaw.join(', ') : (cspRaw || null),
      hasXfo: hasXfo,
      hasCspFrameAncestors: hasFrameAncestors
    },
    iframeBlocked,
    recommendations
  };
};

export const testClickjacking = async (req, res) => {
  let { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });

  try {
    if (!/^https?:\/\//i.test(url)) url = `https://${url}`;
    try { new URL(url); } catch { return res.status(422).json({ error: 'Invalid URL format' }); }

    const response = await axios({
      method: 'HEAD',
      url,
      maxRedirects: 5,
      timeout: 8000,
      validateStatus: () => true,
    });

    if (response.status >= 400) {
      return res.status(400).json({ error: `Could not access site. Status code: ${response.status}` });
    }

    const lower = Object.fromEntries(Object.entries(response.headers).map(([k, v]) => [k.toLowerCase(), v]));
    const { 
      isProtected, protectedBy, severity, headers, iframeBlocked, recommendations 
    } = computeResult(lower['x-frame-options'], lower['content-security-policy']);

    const record = new ClickjackingTest({ url, isProtected, protectedBy, severity });
    await record.save();

    res.status(200).json({
      url,
      isProtected,
      protectedBy,
      severity,
      headers,
      iframeBlocked,
      recommendations
    });
  } catch (err) {
    console.error('Clickjacking test error:', err.message);
    res.status(500).json({ error: 'Failed to fetch URL or analyze headers' });
  }
};
