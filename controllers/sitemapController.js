import { Sitemap } from '../models/sitemapModel.js';
import crawlWebsite from '../utils/crawler.js';
import fetch from 'node-fetch';

const STATUS_TEXT = {
  200: 'OK', 201: 'Created', 204: 'No Content',
  301: 'Moved Permanently', 302: 'Found', 303: 'See Other', 307: 'Temporary Redirect', 308: 'Permanent Redirect',
  400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found', 410: 'Gone',
  429: 'Too Many Requests',
  500: 'Internal Server Error', 502: 'Bad Gateway', 503: 'Service Unavailable', 504: 'Gateway Timeout'
};

export const generateSitemap = async (req, res) => {
  try {
    const { url, depth } = req.body;
    if (!url || !depth) {
      return res.status(400).json({ error: true, message: 'URL and depth are required' });
    }
    // validate URL
    try { new URL(url); } catch { return res.status(400).json({ error: true, message: 'Invalid URL format' }); }
    const maxDepth = parseInt(depth, 10);
    if (isNaN(maxDepth) || maxDepth < 1) {
      return res.status(400).json({ error: true, message: 'Depth must be a positive integer' });
    }
    if (maxDepth > 5) return res.status(400).json({ error: true, message: 'Depth too large, max allowed is 5' });
    if (url.length > 2048) return res.status(400).json({ error: true, message: 'URL too long' });

    const start = Date.now();
    const urls = await crawlWebsite(url, maxDepth); // array of absolute URLs
    const duration = (Date.now() - start) / 1000;
    console.log(`Crawled ${urls.length} pages in ${duration}s`);

    // Check each URL for status / redirect hops (with small concurrency)
    const urlDetails = await checkUrlsWithConcurrency(urls, 8);

    const redirected = urlDetails.filter(u => (u.redirectHops || 0) > 0 && is2xx(u.status)).length;
    const broken = urlDetails.filter(u => isBroken(u.status)).length;
    const avgUrlLength = Math.round((urls.reduce((acc, u) => acc + (u?.length || 0), 0) / (urls.length || 1)) || 0);

    const xml = generateXml(urls);

    // persist
    const entry = new Sitemap({
      domain: new URL(url).hostname,
      depth: maxDepth,
      urls,
      xml
    });
    await entry.save();

    return res.status(200).json({
      error: false,
      pagesFound: urls.length,
      urls,
      xml,
      urlDetails, // [{url, status, statusText, finalUrl, redirectHops}]
      summary: {
        totalPages: urls.length,
        crawlDepth: maxDepth,
        redirected,
        broken,
        avgUrlLength
      }
    });
  } catch (err) {
    console.error('Error generating sitemap:', err);
    return res.status(500).json({ error: true, message: 'Internal Server Error' });
  }
};

/* ------------ helpers ------------ */

function isBroken(status) {
  if (typeof status !== 'number') return true; // ERROR, etc.
  return status >= 400;
}
function is2xx(status) {
  return typeof status === 'number' && status >= 200 && status < 300;
}

async function checkUrlsWithConcurrency(urls, limit = 8) {
  const results = [];
  let i = 0;

  async function worker() {
    while (i < urls.length) {
      const idx = i++;
      const u = urls[idx];
      try {
        const meta = await fetchWithRedirects(u, 5, 15000);
        results[idx] = {
          url: u,
          status: meta.status,
          statusText: meta.statusText || '',
          finalUrl: meta.finalUrl,
          redirectHops: meta.hops
        };
      } catch (e) {
        results[idx] = {
          url: u,
          status: 'ERROR',
          statusText: 'Network Error',
          finalUrl: u,
          redirectHops: 0
        };
      }
    }
  }

  const workers = Array.from({ length: Math.min(limit, urls.length || 1) }, () => worker());
  await Promise.all(workers);
  return results;
}

async function fetchWithRedirects(url, maxHops = 5, timeoutMs = 15000) {
  let current = url;
  let hops = 0;

  while (hops <= maxHops) {
    const res = await fetch(current, { redirect: 'manual', timeout: timeoutMs }).catch(() => null);
    if (!res) {
      return { finalUrl: current, status: 'ERROR', statusText: 'Network Error', hops };
    }
    if ([301, 302, 303, 307, 308].includes(res.status)) {
      const loc = res.headers.get('location');
      if (!loc) return { finalUrl: current, status: res.status, statusText: STATUS_TEXT[res.status] || '', hops };
      const next = toAbsolute(loc, current);
      if (!next) return { finalUrl: current, status: 'ERROR', statusText: 'Bad Redirect', hops };
      current = next;
      hops++;
      continue;
    }
    return { finalUrl: current, status: res.status, statusText: STATUS_TEXT[res.status] || '', hops };
  }
  return { finalUrl: current, status: 'ERROR', statusText: 'Too Many Redirects', hops };
}

function toAbsolute(href, baseUrl) {
  try { return new URL(href, baseUrl).toString(); } catch { return null; }
}

function escapeXml(unsafe) {
  return unsafe.replace(/[<>&'"]/g, (c) => {
    switch (c) {
      case '<': return '&lt;';
      case '>': return '&gt;';
      case '&': return '&amp;';
      case '\'': return '&apos;';
      case '"': return '&quot;';
      default: return c;
    }
  });
}

function generateXml(urls) {
  const xmlUrls = urls.map(u => `<url><loc>${escapeXml(u)}</loc></url>`).join('');
  return `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${xmlUrls}</urlset>`;
}
