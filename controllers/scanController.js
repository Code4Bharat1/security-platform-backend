// controllers/scanController.js
import sslChecker from 'ssl-checker';
import axios from 'axios';
import https from 'https';
import ScanResult from '../models/scanResultModel.js';
import * as cheerio from 'cheerio';
import { XMLParser } from 'fast-xml-parser';
import { parseStringPromise } from 'xml2js';

/* ========== Helpers (reused/extended) ========== */

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

    if (hasSecure) flags.push('Secure');
    if (hasHttpOnly) flags.push('HttpOnly');
    if (sameSite) flags.push(sameSite);

    if (!hasSecure)   issues.push('Missing Secure');
    if (!hasHttpOnly) issues.push('Missing HttpOnly');
    if (!sameSite)    issues.push('Missing SameSite');

    findings.push({
      name,
      raw,
      flags,
      issues,
      attributes: { hasDomain: !!hasDomain, hasPath: !!hasPath }
    });
  }
  return findings;
}

function analyzeCSP(cspHeader) {
  if (!cspHeader || typeof cspHeader !== 'string') {
    return { present: false, issues: ['CSP header not present'] };
  }
  const issues = [];
  const lower = cspHeader.toLowerCase();
  if (!/default-src\s/.test(lower)) issues.push('Missing default-src');
  if (/unsafe-inline/.test(lower)) issues.push('Uses unsafe-inline');
  if (/unsafe-eval/.test(lower)) issues.push('Uses unsafe-eval');
  if (!/frame-ancestors\s/.test(lower)) issues.push('Missing frame-ancestors (clickjacking protection)');
  if (!/upgrade-insecure-requests/.test(lower)) issues.push('Missing upgrade-insecure-requests');
  return { present: true, issues };
}

function countMissingSecurityHeaders(headers) {
  if (!headers) return 5;
  const need = [
    'strict-transport-security',
    'content-security-policy',
    'x-content-type-options',
    'x-frame-options',
    'x-xss-protection'
  ];
  let miss = 0;
  for (const h of need) if (!headers[h]) miss++;
  return miss;
}

function gradeFromMetrics({ vulnCount, missingSecHeaders, weakCookies, cspIssues }) {
  // simple heuristic grade A–F
  const score =
    100
    - vulnCount * 10
    - missingSecHeaders * 8
    - weakCookies * 6
    - cspIssues * 5;
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

// NEW: parse HTML to assess forms for autocomplete, password fields, and insecure actions
function analyzeHTMLForms(html, pageUrl) {
  const findings = {
    formsFound: 0,
    passwordFields: 0,
    insecureActions: [], // http:// action or protocol-relative without https context
    autoCompleteIssues: [], // password inputs without autocomplete hints
  };
  if (!html) return findings;

  const $ = cheerio.load(html);
  const pageIsHttps = /^https:\/\//i.test(pageUrl || '');

  $('form').each((_, form) => {
    findings.formsFound++;
    const $form = $(form);
    const action = ($form.attr('action') || '').trim();

    // insecure action if starts with http:// OR protocol-relative without https page context
    if (/^http:\/\//i.test(action) || (!pageIsHttps && /^\/\//.test(action))) {
      findings.insecureActions.push(action || '(empty)');
    }

    // inputs
    $(form)
      .find('input')
      .each((__, input) => {
        const $in = $(input);
        const type = ($in.attr('type') || '').toLowerCase();
        const ac = ($in.attr('autocomplete') || '').toLowerCase();
        if (type === 'password') {
          findings.passwordFields++;
          // browsers largely ignore disabling autocomplete now, but we flag lack of explicit guidance
          if (!ac || (!/new-password|current-password/i.test(ac) && ac !== 'off')) {
            findings.autoCompleteIssues.push(
              `Password input missing strong autocomplete hint (found: "${ac || 'none'}")`
            );
          }
        }
      });
  });

  return findings;
}

// NEW: robots.txt quick parse
function analyzeRobotsTxt(text) {
  const result = {
    present: !!text,
    allowsAll: false,
    disallowRules: [],
  };
  if (!text) return result;

  // Very simple parse for User-agent: * block
  const lines = text.split(/\r?\n/);
  let uaStar = false;
  for (const line of lines) {
    const l = line.trim();
    if (!l || l.startsWith('#')) continue;
    if (/^user-agent:\s*\*/i.test(l)) {
      uaStar = true;
      continue;
    }
    if (uaStar && /^user-agent:/i.test(l)) {
      // next UA block
      uaStar = false;
      continue;
    }
    if (uaStar && /^disallow:/i.test(l)) {
      const val = l.split(':')[1]?.trim() || '';
      result.disallowRules.push(val);
    }
    if (uaStar && /^allow:/i.test(l)) {
      // If explicitly Allow: / and no Disallow, consider allowsAll
      // We'll compute after loop
    }
  }
  // allowsAll if either no disallow rules or explicit Disallow: (empty) for UA *
  result.allowsAll = result.disallowRules.length === 0 || result.disallowRules.every((d) => d === '');
  return result;
}

// NEW: minimal sitemap summary


async function summarizeSitemap(xml) {
  try {
    const parsed = await parseStringPromise(xml, { explicitArray: false, trim: true });
    
    // Case 1: <urlset> — direct URLs
    if (parsed.urlset && parsed.urlset.url) {
      const urls = Array.isArray(parsed.urlset.url)
        ? parsed.urlset.url.map(u => u.loc).filter(Boolean)
        : [parsed.urlset.url.loc].filter(Boolean);

      return {
        type: 'urlset',
        totalUrls: urls.length,
        urls, // ✅ full list of discovered URLs
      };
    }

    // Case 2: <sitemapindex> — nested sitemaps
    if (parsed.sitemapindex && parsed.sitemapindex.sitemap) {
      const sitemapUrls = Array.isArray(parsed.sitemapindex.sitemap)
        ? parsed.sitemapindex.sitemap.map(m => m.loc).filter(Boolean)
        : [parsed.sitemapindex.sitemap.loc].filter(Boolean);

      return {
        type: 'sitemapindex',
        totalSitemaps: sitemapUrls.length,
        sitemaps: sitemapUrls,
      };
    }

    // Fallback: no recognizable structure
    return { type: 'unknown', note: 'Parsed but unrecognized structure' };
  } catch (err) {
    return { type: 'invalid', note: 'XML parse failed' };
  }
}


/* ========== MAIN ========== */

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
      openPorts: null, // (placeholder for future extension)
      vulnerabilities: [],
      vulnerabilityCount: 0,
      riskLevel: 'low',
      timespan: 0,
      sitemap: null,          // NEW
      robots: null,           // NEW
      htmlAnalysis: null,     // NEW (forms)
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
    let htmlBody = '';
    let finalUrlUsed = formattedUrl;
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
      scanResults.headers = headers;

      const nodeRes = response?.request?.res;
if (nodeRes && Array.isArray(nodeRes.rawHeaders) && nodeRes.rawHeaders.length) {
  // Node provides ["Header","Value","Header","Value",...]
  scanResults.headers.rawHeaders = nodeRes.rawHeaders;
  scanResults.headers.httpVersion = nodeRes.httpVersion || '';
  scanResults.headers.statusCode = nodeRes.statusCode;
  scanResults.headers.statusMessage = nodeRes.statusMessage || '';
} else {
  // Build the same flat array from axios' normalized headers object
  const flat = [];
  for (const [k, v] of Object.entries(headers)) {
    flat.push(k, Array.isArray(v) ? v.join(', ') : String(v));
  }
  scanResults.headers.rawHeaders = flat;
}


      // Missing security headers
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
scanResults.headers.cookieFindings = cookieFindings;   // ⬅️ use a unique key
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

      // NEW: Fetch HTML (follow redirects) to analyze forms/autocomplete/clickjacking more precisely
      try {
        const agentFollow = new https.Agent({ rejectUnauthorized: false });
        const htmlResp = await axios.get(formattedUrl, {
          timeout: 8000,
          httpsAgent: agentFollow,
          validateStatus: () => true,
          maxRedirects: 5,
          responseType: 'text',
          transformResponse: [(d) => d] // keep as string
        });
        htmlBody = typeof htmlResp.data === 'string' ? htmlResp.data : '';
        finalUrlUsed = htmlResp.request?.res?.responseUrl || formattedUrl;
      } catch { /* non-fatal */ }

      // NEW: Clickjacking high-confidence flag (both XFO missing and CSP lacks frame-ancestors)
      const xfoMissing = !headers['x-frame-options'];
      const cspLacksFrameAncestors =
        !scanResults.headers?.csp?.present ||
        scanResults.headers?.csp?.issues?.some((i) => /frame-ancestors/i.test(i));
      if (xfoMissing && cspLacksFrameAncestors) {
        scanResults.vulnerabilities.push({
          type: 'clickjacking',
          severity: 'high',
          description: 'Web Application Potentially Vulnerable to Clickjacking',
          details: 'X-Frame-Options missing and CSP lacks frame-ancestors',
          recommendation: 'Set X-Frame-Options: DENY or SAMEORIGIN and add CSP frame-ancestors'
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
        } catch { /* ignore */ }
      })
    );

    // ========== NEW SEGMENT: Web-App specific checks ==========

    // A) Analyze HTML for forms (autocomplete + password usage + insecure actions)
    try {
      if (!htmlBody) {
        // try once more if we didn’t get it earlier
        const agentFollow = new https.Agent({ rejectUnauthorized: false });
        const htmlResp = await axios.get(`https://${domain}`, {
          timeout: 8000,
          httpsAgent: agentFollow,
          validateStatus: () => true,
          maxRedirects: 5,
          responseType: 'text',
          transformResponse: [(d) => d]
        });
        htmlBody = typeof htmlResp.data === 'string' ? htmlResp.data : '';
        finalUrlUsed = htmlResp.request?.res?.responseUrl || `https://${domain}`;
      }
      const formAnalysis = analyzeHTMLForms(htmlBody, finalUrlUsed);
      scanResults.htmlAnalysis = formAnalysis;

      // Password auto-completion
      if (formAnalysis.passwordFields > 0 && formAnalysis.autoCompleteIssues.length > 0) {
        scanResults.vulnerabilities.push({
          type: 'autocomplete',
          severity: 'low',
          description: 'Web Server Allows Password Auto-Completion',
          details: formAnalysis.autoCompleteIssues.slice(0, 5).join(' | '),
          recommendation:
            'Use autocomplete="new-password" or "current-password" on password fields; consider password managers compatibility'
        });
      }

      // Insecure form actions
      if (formAnalysis.insecureActions.length > 0) {
        scanResults.vulnerabilities.push({
          type: 'cleartext_credentials',
          severity: 'high',
          description: 'Web Server Transmits Cleartext Credentials',
          details: `Forms submit to insecure endpoints: ${formAnalysis.insecureActions.slice(0,3).join(', ')}`,
          recommendation: 'Ensure all form actions use HTTPS and enable HSTS (includeSubDomains; preload)'
        });
      }
    } catch { /* non-fatal */ }

    // B) HTTP (cleartext) availability check
    try {
      const httpResp = await axios.get(`http://${domain}`, {
        timeout: 5000,
        validateStatus: () => true,
        maxRedirects: 0
      });
      // If HTTP root is 200 OK (no redirect to HTTPS) -> high risk
      const loc = httpResp.headers?.location || '';
      const upgradesToHttps = /^https:\/\//i.test(loc);
      if (httpResp.status === 200 || (httpResp.status >= 300 && httpResp.status < 400 && !upgradesToHttps)) {
        scanResults.vulnerabilities.push({
          type: 'cleartext_http',
          severity: 'high',
          description: 'Web Server Accessible over HTTP without forced HTTPS',
          details: `HTTP GET / returned ${httpResp.status}${loc ? ` (Location: ${loc})` : ''}`,
          recommendation: 'Redirect all HTTP to HTTPS with 301 and enable HSTS'
        });
      }
    } catch { /* ignore network errors */ }


// 🧩 C + D) Sitemap and robots.txt (domain / subdomain aware)
try {
  const isSubdomain = domain.split(".").length > 2;
  const robotsUrl = `https://${domain}/robots.txt`;
  const sitemapCandidates = [
    `https://${domain}/sitemap.xml`,
    `https://${domain}/sitemap_index.xml`,
    `https://${domain}/sitemaps/sitemap.xml`,
    `https://${domain}/wp-sitemap.xml`,
    `https://${domain}/post-sitemap.xml`,
    `https://${domain}/page-sitemap.xml`,
    `https://${domain}/sitemap-index.xml`,
  ];

  let sitemapData = null;
  let sitemapUrl = null;
  let robotsMeta = {
    present: false,
    scope: isSubdomain ? "subdomain" : "domain",
  };

  // 🔹 1️⃣ Fetch robots.txt
  try {
    const resp = await axios.get(robotsUrl, {
      timeout: 6000,
      httpsAgent: new https.Agent({ rejectUnauthorized: false }),
      validateStatus: () => true,
      responseType: "text",
    });

    if (resp.status === 200 && typeof resp.data === "string" && resp.data.trim()) {
      const text = resp.data.trim();
      const disallowRules = [...text.matchAll(/^Disallow:\s*(.+)$/gim)].map((m) =>
        m[1].trim()
      );
      const allowRules = [...text.matchAll(/^Allow:\s*(.+)$/gim)].map((m) =>
        m[1].trim()
      );
      const sitemapRefs = [...text.matchAll(/^Sitemap:\s*(https?:\/\/[^\s]+)/gim)].map(
        (m) => m[1].trim()
      );
      const userAgents = [...text.matchAll(/^User-agent:\s*(.+)$/gim)].map((m) =>
        m[1].trim()
      );
      const allowsAll = userAgents.some((ua) => ua === "*") && disallowRules.length === 0;

      robotsMeta = {
        present: true,
        scope: isSubdomain ? "subdomain" : "domain",
        allowsAll,
        disallowCount: disallowRules.length,
        allowCount: allowRules.length,
        allowRules,
        disallowRules,

        sitemapsInRobots: sitemapRefs,
        fetchedUrl: robotsUrl,
      };

      // 🔸 Add any valid robots.txt sitemap links to candidates
      for (const link of sitemapRefs) {
        if (link.includes(domain)) sitemapCandidates.unshift(link);
      }
    } else {
      robotsMeta = {
        present: false,
        scope: isSubdomain ? "subdomain" : "domain",
        reason: `robots.txt not found or empty for this ${isSubdomain ? "subdomain" : "domain"}.`,
      };
    }
  } catch {
    robotsMeta = {
      present: false,
      scope: isSubdomain ? "subdomain" : "domain",
      reason: "robots.txt request failed.",
    };
  }

  // 🔹 2️⃣ Try to fetch any sitemap (including ones found in robots.txt)
  for (const candidate of sitemapCandidates) {
    try {
      const sm = await axios.get(candidate, {
        timeout: 7000,
        httpsAgent: new https.Agent({ rejectUnauthorized: false }),
        validateStatus: () => true,
        responseType: "text",
        transformResponse: [(d) => d],
      });

      const contentType = sm.headers["content-type"] || "";
      const looksXml =
        /xml/i.test(contentType) ||
        /<(urlset|sitemapindex)[^>]*>/i.test(sm.data);

      if (sm.status >= 200 && sm.status < 400 && looksXml) {
        sitemapData = sm.data;
        sitemapUrl = candidate;
        break;
      }
    } catch {
      /* continue */
    }
  }

  // 🔹 3️⃣ Build final scan results
  scanResults.robots = robotsMeta;

  if (sitemapData) {
    const summary = await summarizeSitemap(sitemapData);
    scanResults.sitemap = {
      present: true,
      url: sitemapUrl,
      scope: isSubdomain ? "subdomain" : "domain",
      summary,
      foundVia:
        robotsMeta.sitemapsInRobots?.includes(sitemapUrl) &&
        robotsMeta.present
          ? "robots.txt"
          : "direct",
    };
  } else {
    scanResults.sitemap = {
      present: false,
      scope: isSubdomain ? "subdomain" : "domain",
      reason: `No sitemap found for this ${isSubdomain ? "subdomain" : "domain"}.`,
    };
  }
} catch {
  scanResults.sitemap = { present: false };
}

// 🧩 E) HTML Analysis
// 🧩 HTML Analysis (Improved + Accurate)
try {
  const pagesToScan = [
    `https://${domain}`,                 // homepage
    `https://${domain}/contact-us`,     // common contact page
  ];

  let formsFound = 0;
  let passwordFields = 0;
  const insecureActions = [];
  const autoCompleteIssues = [];

  for (const url of pagesToScan) {
    try {
      const res = await axios.get(url, {
        timeout: 7000,
        httpsAgent: new https.Agent({ rejectUnauthorized: false }),
        validateStatus: () => true,
        responseType: "text",
      });

      if (res.status === 200 && typeof res.data === "string") {
        // Normalize HTML (helps regex work on minified HTML)
        const html = res.data.replace(/\s+/g, " ");

        // ✅ Count all forms
        const forms = html.match(/<form[\s\S]*?>/gi) || [];
        formsFound += forms.length;

        // ✅ Count password fields
        const pwFields = html.match(/<input[^>]*type=["']?password["']?/gi) || [];
        passwordFields += pwFields.length;

        // ✅ Detect insecure (http://) form actions
        const insecure = html.match(/<form[^>]*action=["']http:\/\/[^"']+/gi) || [];
        insecure.forEach((m) => insecureActions.push(m));

        // ✅ Detect weak/missing autocomplete on password inputs
        pwFields.forEach((input) => {
          const hasStrong = /autocomplete=["']?(new-password|current-password)["']?/i.test(input);
          if (!hasStrong)
            autoCompleteIssues.push("Password input missing strong autocomplete hint (found: none)");
        });
      }
    } catch { /* ignore individual pages */ }
  }

  scanResults.htmlAnalysis = {
    formsFound,
    passwordFields,
    insecureActions,
    autoCompleteIssues,
  };
} catch {
  scanResults.htmlAnalysis = {
    formsFound: 0,
    passwordFields: 0,
    insecureActions: [],
    autoCompleteIssues: [],
  };
}




    // f) “Web Application Cookies Not Marked Secure”
const cookieArr = scanResults.headers?.cookieFindings || []; // fallback optional: || scanResults.headers?.cookies || []
const insecureCookies = cookieArr.filter((c) => c.issues.includes('Missing Secure'));
    if (insecureCookies.length > 0) {
      scanResults.vulnerabilities.push({
        type: 'cookie_secure',
        severity: 'medium',
        description: 'Web Application Cookies Not Marked Secure',
        details: `Cookies: ${insecureCookies.slice(0, 5).map((c) => c.name).join(', ')}`,
        recommendation: 'Mark cookies as Secure; consider SameSite=Strict/Lax and HttpOnly'
      });
    }

    // ========== END new web-app segment ==========

    // 4) Final tallies
    scanResults.vulnerabilityCount = scanResults.vulnerabilities.length;
    scanResults.riskLevel =
      scanResults.vulnerabilityCount > 5 ? 'high' :
      scanResults.vulnerabilityCount > 2 ? 'medium' : 'low';

    // 5) Benchmark vs last 10 scans for same domain
    const SAMPLE_N = 10;
    const prevScans = await ScanResult.find({ domain }).sort({ timestamp: -1 }).limit(SAMPLE_N);
    if (prevScans.length) {
      const missingNow = countMissingSecurityHeaders(scanResults.headers || {});
      const weakCookiesNow = (scanResults.headers?.cookies || []).filter((c) => c.issues.length).length;
      const cspIssuesNow = scanResults.headers?.csp?.issues?.length || 0;

      const avg = (arr) => (arr.length ? arr.reduce((a, b) => a + b, 0) / arr.length : 0);

      const prevMissing = avg(prevScans.map((s) => countMissingSecurityHeaders(s.headers || {})));
      const prevWeakCookies = avg(
  prevScans.map((s) => {
    const arr = s.headers?.cookieFindings || s.headers?.cookies || [];
    return arr.filter((c) => c.issues?.length).length;
  })
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
      error: 'Failed to complete scan',
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
  