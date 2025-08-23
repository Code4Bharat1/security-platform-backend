import fetch from 'node-fetch';              // If Node 18+, you can use global fetch
import { load } from 'cheerio';

export const analyzeMetaTags = async (req, res) => {
  try {
    const { url } = req.body || {};
    if (!url) return res.status(400).json({ error: 'URL is required' });

    // Fetch HTML (follow redirects)
    const resp = await fetch(url, { redirect: 'follow' });
    const finalUrl = resp.url || url;
    const status = resp.status;
    const headers = headerLowerMap(resp.headers);

    const html = await resp.text();
    const $ = load(html);

    // Collect meta & link tags
    const meta = [];
    $('meta').each((_, el) => {
      const name = $(el).attr('name') || $(el).attr('property') || $(el).attr('http-equiv');
      const content = $(el).attr('content');
      if (name && (content ?? '') !== '') meta.push({ name, content });
    });
    const links = [];
    $('link').each((_, el) => {
      const rel = ($(el).attr('rel') || '').toLowerCase();
      const href = $(el).attr('href');
      if (rel && href) links.push({ rel, href });
    });

    // SECURITY: headers + meta http-equiv
    const sec = buildSecurityChecks(headers, meta, finalUrl);

    // SEO: description, keywords (deprecated), robots, canonical, OG
    const seo = buildSeoChecks($, links, meta, finalUrl);

    // Duplicates/conflicts
    const duplicates = detectDuplicates($, links, finalUrl, seo.og?.url);

    // Scores
    const scores = computeScores(sec, seo);

    // CORS (OPTIONS with evil Origin; fall back to HEAD if blocked)
    const cors = await analyzeCORS(finalUrl);

    const result = {
      targetUrl: url,
      fetchedUrl: finalUrl,
      httpStatus: status,
      timestamp: new Date().toISOString(),
      headers: pickHeaders(headers, [
        'content-security-policy',
        'x-frame-options',
        'referrer-policy',
        'x-content-type-options',
        'strict-transport-security',
      ]),
      meta,
      security: sec,
      seo,
      duplicates,
      og: seo.og,
      scores,
      cors,
    };

    return res.json(result);
  } catch (err) {
    console.error('meta-analyze error:', err);
    return res.status(500).json({ error: 'Server error while analyzing meta tags' });
  }
};

/* ---------------- helpers ---------------- */

function headerLowerMap(hs) {
  const out = {};
  for (const [k, v] of hs.entries()) out[String(k).toLowerCase()] = v;
  return out;
}

function pickHeaders(map, keys) {
  const o = {};
  keys.forEach((k) => (o[k] = map[k] || undefined));
  return o;
}

function buildSecurityChecks(headers, meta, finalUrl) {
  const getMetaHttp = (key) =>
    meta.find((m) => (m.name || '').toLowerCase() === key.toLowerCase())?.content;

  // Prefer headers; if missing, look for meta http-equiv
  const csp = headers['content-security-policy'] || getMetaHttp('content-security-policy');
  const xfo = headers['x-frame-options'] || getMetaHttp('x-frame-options');
  const refpol = headers['referrer-policy'] || getMetaHttp('referrer-policy');
  const xcto = headers['x-content-type-options'] || getMetaHttp('x-content-type-options');
  const hsts = headers['strict-transport-security']; // header only

  const checks = [];

  checks.push({
    key: 'Content-Security-Policy',
    exists: !!csp,
    value: csp || '',
    severity: 'HIGH',
    note: 'Mitigates XSS/data injection',
    suggestion: csp
      ? ''
      : "Add CSP, e.g. `Content-Security-Policy: default-src 'self';`",
  });

  const xfoOk = xfo && /^(deny|sameorigin)$/i.test(xfo.trim());
  checks.push({
    key: 'X-Frame-Options',
    exists: !!xfo,
    value: xfo || '',
    severity: xfoOk ? 'LOW' : 'HIGH',
    note: 'Prevents clickjacking',
    suggestion: xfoOk ? '' : 'Use `DENY` or `SAMEORIGIN`',
  });

  const refOk =
    refpol &&
    /^(no-referrer|strict-origin|strict-origin-when-cross-origin|same-origin)$/i.test(refpol.trim());
  checks.push({
    key: 'Referrer-Policy',
    exists: !!refpol,
    value: refpol || '',
    severity: refOk ? 'LOW' : 'MEDIUM',
    note: 'Controls referrer leakage',
    suggestion: refOk ? '' : "Use `no-referrer` or `strict-origin-when-cross-origin`",
  });

  const nosniff = xcto && /^nosniff$/i.test(xcto.trim());
  checks.push({
    key: 'X-Content-Type-Options',
    exists: !!xcto,
    value: xcto || '',
    severity: nosniff ? 'LOW' : 'MEDIUM',
    note: 'Prevents MIME sniffing',
    suggestion: nosniff ? '' : "Set `X-Content-Type-Options: nosniff`",
  });

  const isHttps = /^https:/i.test(finalUrl || '');
  checks.push({
    key: 'Strict-Transport-Security',
    exists: !!hsts,
    value: hsts || '',
    severity: isHttps ? (hsts ? 'LOW' : 'HIGH') : 'MEDIUM',
    note: 'Forces HTTPS (HSTS)',
    suggestion: isHttps
      ? hsts
        ? ''
        : "Set `Strict-Transport-Security: max-age=15552000; includeSubDomains; preload`"
      : 'Enable HTTPS first, then configure HSTS',
  });

  return { checks };
}

function buildSeoChecks($, links, meta, finalUrl) {
  // Description
  const descriptions = $('meta[name="description"]');
  const descContent = descriptions.first().attr('content') || '';
  const descLen = descContent.trim().length;
  const descStatus = descContent
    ? descLen >= 50 && descLen <= 160
      ? 'OK'
      : 'Warning'
    : 'Missing';

  // Keywords (deprecated)
  const keywords = $('meta[name="keywords"]').length > 0;

  // Robots
  const robots = $('meta[name="robots"]').attr('content') || '';
  const robotsLower = robots.toLowerCase();
  const robotsIssue = robotsLower.includes('noindex') || robotsLower.includes('nofollow');

  // Canonical
  const canon = links.find((l) => l.rel === 'canonical')?.href;

  // OG
  const og = {
    title: $('meta[property="og:title"]').attr('content') || '',
    description: $('meta[property="og:description"]').attr('content') || '',
    image: $('meta[property="og:image"]').attr('content') || '',
    url: $('meta[property="og:url"]').attr('content') || '',
  };

  const checks = [
    {
      key: 'meta:description',
      status: descStatus === 'OK' ? 'Good' : descStatus === 'Warning' ? 'Warning' : 'Missing',
      detail: descContent ? `Length: ${descLen} chars` : '',
      suggestion: !descContent
        ? 'Add a compelling description (150–160 chars).'
        : descLen < 50
        ? 'Increase length; aim for 150–160 chars.'
        : descLen > 160
        ? 'Reduce length; aim for 150–160 chars.'
        : '',
    },
    {
      key: 'meta:keywords',
      status: keywords ? 'Deprecated' : 'Not present (OK)',
      detail: keywords ? 'Search engines ignore this tag now.' : '',
      suggestion: keywords ? 'Remove keywords tag.' : '',
    },
    {
      key: 'meta:robots',
      status: robots ? 'Present' : 'Missing',
      detail: robots || '',
      suggestion: robotsIssue ? 'Avoid `noindex`/`nofollow` on indexable pages.' : '',
    },
    {
      key: 'link:canonical',
      status: canon ? 'Present' : 'Missing',
      detail: canon || '',
      suggestion: canon ? '' : 'Add canonical link to preferred URL.',
    },
    {
      key: 'Open Graph',
      status: og.title || og.description || og.image ? 'Present' : 'Missing',
      detail: `title=${og.title ? 'y' : 'n'} desc=${og.description ? 'y' : 'n'} image=${og.image ? 'y' : 'n'}`,
      suggestion: og.title && og.description && og.image ? '' : 'Add/complete OG tags for social previews.',
    },
  ];

  return { checks, og };
}

function detectDuplicates($, links, finalUrl, ogUrl) {
  const dups = [];
  const descCount = $('meta[name="description"]').length;
  if (descCount > 1) dups.push({ issue: `Duplicate meta:description (${descCount} instances)` });

  const canonicalLinks = links.filter((l) => l.rel === 'canonical');
  if (canonicalLinks.length > 1) dups.push({ issue: `Duplicate canonical links (${canonicalLinks.length})` });

  // og:url conflict
  try {
    if (ogUrl) {
      const f = new URL(finalUrl);
      const o = new URL(ogUrl, finalUrl);
      if (o.origin + o.pathname !== f.origin + f.pathname) {
        dups.push({
          issue: 'og:url differs from actual page URL',
          detail: `og:url=${o.href} vs page=${f.href}`,
        });
      }
    }
  } catch {}
  return dups;
}

function computeScores(security, seo) {
  // Security out of 10
  let sec = 10;
  (security.checks || []).forEach((c) => {
    if (!c.exists) sec -= c.severity === 'HIGH' ? 3 : 1;
    else {
      if (c.key === 'X-Frame-Options' && !/^(deny|sameorigin)$/i.test(c.value || '')) sec -= 1;
      if (c.key === 'X-Content-Type-Options' && !/^nosniff$/i.test(c.value || '')) sec -= 1;
      if (c.key === 'Referrer-Policy') {
        const ok = /^(no-referrer|strict-origin|strict-origin-when-cross-origin|same-origin)$/i.test(c.value || '');
        if (!ok) sec -= 1;
      }
    }
  });
  sec = Math.max(0, Math.min(10, sec));

  // SEO out of 10
  let seoScore = 10;
  (seo.checks || []).forEach((c) => {
    if (/missing/i.test(c.status)) seoScore -= 2;
    if (/deprecated/i.test(c.status)) seoScore -= 1;
    if (c.key === 'meta:description' && /warning/i.test(c.status)) seoScore -= 1;
  });
  seoScore = Math.max(0, Math.min(10, seoScore));

  const total = Math.round(((sec + seoScore) / 20) * 10 * 10) / 10; // 0–10, 1dp
  return { security: sec, seo: seoScore, total };
}

async function analyzeCORS(targetUrl) {
  try {
    const optionsResp = await fetch(targetUrl, {
      method: 'OPTIONS',
      headers: {
        Origin: 'https://evil.com',
        'Access-Control-Request-Method': 'GET',
      },
      redirect: 'follow',
    }).catch(() => null);

    if (!optionsResp) return { error: 'OPTIONS request failed' };

    const h = headerLowerMap(optionsResp.headers);
    let verdict = 'Moderate';
    const recs = [];

    const allowOrigin = h['access-control-allow-origin'] || 'Not Present';
    const allowCreds = h['access-control-allow-credentials'] || 'Not Present';
    const allowMethods = h['access-control-allow-methods'] || 'Not Present';
    const allowHeaders = h['access-control-allow-headers'] || 'Not Present';
    const exposeHeaders = h['access-control-expose-headers'] || 'Not Present';

    // Checks
    const wildcard = allowOrigin === '*';
    const reflectsOrigin = allowOrigin === 'https://evil.com';
    const credsTrue = /true/i.test(allowCreds);

    const methods = (allowMethods || '').toUpperCase();
    const headers = (allowHeaders || '').toLowerCase();

    if (wildcard && credsTrue) {
      verdict = 'Vulnerable: * with credentials';
      recs.push('Avoid wildcard (*) when credentials are allowed.');
    } else if (reflectsOrigin && credsTrue) {
      verdict = 'Weak: Reflecting Origin with credentials';
      recs.push('Do not dynamically reflect Origin when credentials are allowed.');
    } else if (reflectsOrigin) {
      verdict = 'Weak: Dynamic Origin reflection';
      recs.push('Prefer an allowlist of trusted origins; avoid reflecting request Origin.');
    }

    if (methods.includes('DELETE') || methods.includes('PUT') || methods.includes('PATCH')) {
      recs.push('Restrict allowed methods to only what is required (avoid DELETE/PUT/PATCH unless needed).');
    }
    if (headers.includes('authorization')) {
      recs.push('Avoid allowing Authorization header unless essential.');
    }

    if (!recs.length && !wildcard && !reflectsOrigin && !credsTrue) {
      verdict = 'Reasonable';
    }

    return {
      headers: {
        allow_origin: allowOrigin,
        allow_credentials: allowCreds,
        allow_methods: allowMethods,
        allow_headers: allowHeaders,
        expose_headers: exposeHeaders,
      },
      verdict,
      recommendations: recs,
    };
  } catch (e) {
    return { error: e.message || 'CORS analysis failed' };
  }
}
