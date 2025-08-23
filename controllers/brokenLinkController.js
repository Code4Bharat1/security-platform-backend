// controllers/brokenLinkController.js
import fetch from 'node-fetch';
import { parse } from 'node-html-parser';
import { BrokenLinkScan } from '../models/brokenLinkModel.js';

const STATUS_TEXT = {
  200: 'OK', 201: 'Created', 204: 'No Content',
  301: 'Moved Permanently', 302: 'Found', 307: 'Temporary Redirect', 308: 'Permanent Redirect',
  400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found', 410: 'Gone',
  429: 'Too Many Requests',
  500: 'Internal Server Error', 502: 'Bad Gateway', 503: 'Service Unavailable', 504: 'Gateway Timeout'
};

function toAbsolute(href, baseUrl) {
  try { return new URL(href, baseUrl).toString(); } catch { return null; }
}

function scopeOf(linkUrl, baseUrl) {
  try {
    const a = new URL(linkUrl);
    const b = new URL(baseUrl);
    return (a.hostname === b.hostname) ? 'internal' : 'external';
  } catch { return 'external'; }
}

function domLocation(el) {
  const path = [];
  let cur = el;
  while (cur && cur.tagName) {
    path.unshift(cur.tagName.toLowerCase());
    cur = cur.parentNode;
  }
  const joined = path.join('>');
  if (joined.includes('header')) return 'header';
  if (joined.includes('footer')) return 'footer';
  if (joined.includes('nav')) return 'nav';
  if (joined.includes('aside')) return 'aside';
  if (/sitemap/i.test(joined)) return 'sitemap';
  return 'body';
}

function severityOf(status, hopCount = 0) {
  if (typeof status === 'number') {
    if (status >= 500 || (status >= 400 && status !== 429)) return 'critical';
    if ((status >= 300 && hopCount > 1) || status === 429) return 'warning';
    if (status === 200) return 'healthy';
  }
  return 'critical'; // network error etc.
}

function basicPriorityScore({ status, scope, location }) {
  // 1–100 heuristic: external footer/homepage-ish links hit higher if broken
  let score = 20;
  if (status >= 400) score += 40;
  if (scope === 'external') score += 10;
  if (location === 'header' || location === 'footer' || location === 'nav') score += 20;
  return Math.min(100, score);
}

function suggestFix(linkUrl) {
  try {
    const u = new URL(linkUrl);
    if (u.protocol === 'http:') {
      const https = `https://${u.host}${u.pathname}${u.search}${u.hash}`;
      return `Try HTTPS: ${https}`;
    }
  } catch {}
  return '';
}

async function fetchWithRedirects(url, maxHops = 5, timeoutMs = 15000) {
  let current = url;
  let hops = 0;
  let lastStatus = 0;

  while (hops <= maxHops) {
    const res = await fetch(current, { redirect: 'manual', timeout: timeoutMs }).catch(() => null);
    if (!res) {
      return { finalUrl: current, status: 'ERROR', statusText: 'Network Error', hops };
    }
    lastStatus = res.status;
    if ([301,302,303,307,308].includes(res.status)) {
      const loc = res.headers.get('location');
      if (!loc) return { finalUrl: current, status: res.status, statusText: STATUS_TEXT[res.status] || '', hops };
      const next = toAbsolute(loc, current);
      if (!next) return { finalUrl: current, status: 'ERROR', statusText: 'Bad Redirect', hops };
      current = next;
      hops++;
      continue;
    }
    // final
    return { finalUrl: current, status: res.status, statusText: STATUS_TEXT[res.status] || '', hops };
  }
  return { finalUrl: current, status: 'ERROR', statusText: 'Too Many Redirects', hops };
}

export const streamBrokenLinks = async (req, res) => {
  const pageUrl = req.query.url;
  if (!pageUrl) return res.status(400).json({ type: 'error', message: 'URL is required' });

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  try {
    const htmlResp = await fetch(pageUrl);
    const html = await htmlResp.text();
    const root = parse(html);
    const anchors = root.querySelectorAll('a');

    // Collect (href, anchorText, location, sourcePath)
    const items = [];
    for (const a of anchors) {
      const href = a.getAttribute('href');
      if (!href) continue;
      const abs = toAbsolute(href, pageUrl);
      if (!abs) continue;
      // Keep http(s) only
      if (!/^https?:\/\//i.test(abs)) continue;

      items.push({
        url: abs,
        anchorText: (a.text || '').trim(),
        location: domLocation(a),
        sourcePath: new URL(pageUrl).pathname || '/', // page where found
      });
    }

    // Deduplicate by url+sourcePath
    const seen = new Set();
    const unique = items.filter(i => {
      const k = `${i.url}::${i.sourcePath}`;
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });

    res.write(`data: ${JSON.stringify({ type: 'total', total: unique.length })}\n\n`);

    const results = [];
    for (const it of unique) {
      const meta = await fetchWithRedirects(it.url);

      const scope = scopeOf(it.url, pageUrl);
      const sev = severityOf(meta.status, meta.hops);
      const pri = basicPriorityScore({ status: meta.status, scope, location: it.location });
      const suggestion = suggestFix(it.url);

      const out = {
        type: 'link',
        url: it.url,
        anchorText: it.anchorText,
        location: it.location,
        sourcePath: it.sourcePath,
        finalUrl: meta.finalUrl,
        status: meta.status,
        statusText: meta.statusText,
        redirectHops: meta.hops,
        scope,
        severity: sev,
        priorityScore: pri,
        suggestion: suggestion || undefined,
        ok: meta.status === 200
      };

      results.push(out);
      res.write(`data: ${JSON.stringify(out)}\n\n`);
    }

    // Summaries
    const total = results.length;
    const working = results.filter(r => r.status === 200).length;
    const broken = results.filter(r => typeof r.status === 'number' ? r.status >= 400 : true).length;
    const redirects = results.filter(r => r.redirectHops > 0 && (r.status >= 200 && r.status < 400)).length;

    // Save current scan
    const current = await BrokenLinkScan.create({
      scannedUrl: pageUrl,
      total, working, broken, redirects,
      links: results.map(r => ({
        url: r.url,
        finalUrl: r.finalUrl,
        anchorText: r.anchorText,
        location: r.location,
        sourcePath: r.sourcePath,
        status: r.status,
        statusText: r.statusText,
        redirectHops: r.redirectHops,
        scope: r.scope,
        severity: r.severity,
        priorityScore: r.priorityScore,
        suggestion: r.suggestion || ''
      }))
    });

    // Compare with previous scan for this URL (if any)
    const prev = await BrokenLinkScan.findOne({ scannedUrl: pageUrl, _id: { $ne: current._id } })
      .sort({ createdAt: -1 })
      .lean();

    let diff = null;
    if (prev) {
      // broken diff
      diff = {
        broken: (current.broken ?? 0) - (prev.broken ?? 0),
        fixed: Math.max(0,
          (prev.broken ?? 0) - (current.broken ?? 0)
        )
      };
    }

    const payload = { total, working, broken, redirects, diff };
    res.write(`data: ${JSON.stringify({ type: 'summary', payload })}\n\n`);
    res.write(`data: ${JSON.stringify({ type: 'done' })}\n\n`);
    res.end();
  } catch (error) {
    res.write(`data: ${JSON.stringify({ type: 'error', message: error.message })}\n\n`);
    res.end();
  }
};
