// controllers/scanController.js
import sslChecker from 'ssl-checker';
import axios from 'axios';
import https from 'https';
import tls from 'tls';
import http from 'http';
import dns from 'dns';
import net from 'net';
import { promisify } from 'util';
import ScanResult from '../models/scanResultModel.js';
import * as cheerio from 'cheerio';
import { parseStringPromise } from 'xml2js';
import Traceroute from 'nodejs-traceroute'

// Promisify DNS functions
const resolve4Async = promisify(dns.resolve4);
const reverseAsync = promisify(dns.reverse);

/* ========== Helpers (reused/extended) ========== */

// ✅ Extract root domain from subdomain
function extractRootDomain(domain) {
  const parts = domain.split('.');
  if (parts.length > 2) {
    return parts.slice(-2).join('.');
  }
  return domain;
}

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

    const hasSecure = attrs.some((a) => /^secure$/i.test(a));
    const hasHttpOnly = attrs.some((a) => /^httponly$/i.test(a));
    const sameSite = attrs.find((a) => /^samesite=/i.test(a));
    const hasDomain = attrs.find((a) => /^domain=/i.test(a));
    const hasPath = attrs.find((a) => /^path=/i.test(a));

    if (hasSecure) flags.push('Secure');
    if (hasHttpOnly) flags.push('HttpOnly');
    if (sameSite) flags.push(sameSite);

    if (!hasSecure) issues.push('Missing Secure');
    if (!hasHttpOnly) issues.push('Missing HttpOnly');
    if (!sameSite) issues.push('Missing SameSite');

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
  let score = 100
    - vulnCount * 10
    - missingSecHeaders * 8
    - weakCookies * 6
    - cspIssues * 2;

  if (score < 0) score = 0;

  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

function analyzeHTMLForms(html, pageUrl) {
  const findings = {
    formsFound: 0,
    passwordFields: 0,
    insecureActions: [],
    autoCompleteIssues: [],
    cleartextCredentials: false,
  };
  if (!html) return findings;

  const $ = cheerio.load(html);
  const pageIsHttps = /^https:\/\//i.test(pageUrl || '');

  $('form').each((_, form) => {
    findings.formsFound++;
    const $form = $(form);
    const action = ($form.attr('action') || '').trim();
    const method = ($form.attr('method') || 'get').toLowerCase();

    if (/^http:\/\//i.test(action)) {
      findings.insecureActions.push(action || '(empty)');
      const hasPasswordField = $(form).find('input[type="password"]').length > 0;
      if (hasPasswordField && method === 'post') {
        findings.cleartextCredentials = true;
      }
    }
    if (!pageIsHttps && /^\/\//.test(action)) {
      findings.insecureActions.push(action || '(empty)');
    }

    $(form)
      .find('input')
      .each((__, input) => {
        const $in = $(input);
        const type = ($in.attr('type') || '').toLowerCase();
        const ac = ($in.attr('autocomplete') || '').toLowerCase();

        if (type === 'password') {
          findings.passwordFields++;
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

function analyzeRobotsTxt(text) {
  const result = {
    present: !!text,
    allowsAll: false,
    disallowRules: [],
    sitemaps: [],
  };
  if (!text) return result;

  const lines = text.split(/\r?\n/);
  let uaStar = false;
  for (const line of lines) {
    const l = line.trim();
    if (!l || l.startsWith('#')) continue;

    if (/^sitemap:/i.test(l)) {
      const sitemapUrl = l.split(':').slice(1).join(':').trim();
      result.sitemaps.push(sitemapUrl);
      continue;
    }

    if (/^user-agent:\s*\*/i.test(l)) {
      uaStar = true;
      continue;
    }
    if (uaStar && /^user-agent:/i.test(l)) {
      uaStar = false;
      continue;
    }
    if (uaStar && /^disallow:/i.test(l)) {
      const val = l.split(':')[1]?.trim() || '';
      result.disallowRules.push(val);
    }
  }
  result.allowsAll = result.disallowRules.length === 0 || result.disallowRules.every((d) => d === '');
  return result;
}

async function summarizeSitemap(xml) {
  try {
    const parsed = await parseStringPromise(xml, { explicitArray: false, trim: true });

    if (parsed.urlset && parsed.urlset.url) {
      const urls = Array.isArray(parsed.urlset.url)
        ? parsed.urlset.url.map(u => u.loc).filter(Boolean)
        : [parsed.urlset.url.loc].filter(Boolean);

      return {
        type: 'urlset',
        totalUrls: urls.length,
        urls: urls.slice(0, 100),
      };
    }

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

    return { type: 'unknown', note: 'Parsed but unrecognized structure' };
  } catch (err) {
    return { type: 'invalid', note: 'XML parse failed', error: err.message };
  }
}


/* ========== 🆕 WEB MIRRORING / SITE CRAWLER ========== */

async function crawlWebsite(startUrl, options = {}) {
  const {
    maxPages = 50,
    maxDepth = 3,
    timeout = 30000,
    respectRobotsTxt = true,
    onlySubdomain = true
  } = options;

  const visited = new Set();
  const discovered = new Set();
  const queue = [{ url: startUrl, depth: 0 }];
  const urlMap = {
    pages: [],
    assets: {
      images: new Set(),
      scripts: new Set(),
      stylesheets: new Set(),
      links: new Set()
    },
    structure: {},
    errors: []
  };

  const baseUrl = new URL(startUrl);
  const baseDomain = baseUrl.hostname;

  // Helper: Check if URL is same domain
  function isSameDomain(url) {
    try {
      const urlObj = new URL(url, startUrl);
      if (onlySubdomain) {
        return urlObj.hostname === baseDomain;
      }
      return urlObj.hostname.endsWith(baseDomain.split('.').slice(-2).join('.'));
    } catch {
      return false;
    }
  }

  // Helper: Normalize URL
  function normalizeUrl(url) {
    try {
      const urlObj = new URL(url, startUrl);
      urlObj.hash = ''; // Remove fragment
      return urlObj.href;
    } catch {
      return null;
    }
  }

  console.log(`[Web Mirror] Starting crawl of ${startUrl}`);

  // Main crawl loop
  while (queue.length > 0 && visited.size < maxPages) {
    const { url, depth } = queue.shift();

    if (visited.has(url) || depth > maxDepth) continue;

    visited.add(url);

    try {
      console.log(`[Web Mirror] Crawling: ${url} (depth: ${depth}, visited: ${visited.size}/${maxPages})`);

      const agent = new https.Agent({ rejectUnauthorized: false });
      const response = await axios.get(url, {
        timeout,
        httpsAgent: agent,
        headers: {
          'User-Agent': 'SecurityScanner/1.0 (Web Mirror)',
          'Accept': 'text/html,application/xhtml+xml'
        },
        maxRedirects: 5,
        validateStatus: (status) => status < 400
      });

      const contentType = response.headers['content-type'] || '';

      if (!contentType.includes('text/html')) {
        continue;
      }

      const html = response.data;
      const $ = cheerio.load(html);

      const pageInfo = {
        url,
        depth,
        title: $('title').text() || 'No Title',
        statusCode: response.status,
        size: Buffer.byteLength(html, 'utf8'),
        contentType,
        timestamp: new Date().toISOString(),
        links: []
      };

      // Extract all links
      $('a[href]').each((i, elem) => {
        const href = $(elem).attr('href');
        const normalizedUrl = normalizeUrl(href);

        if (normalizedUrl && isSameDomain(normalizedUrl)) {
          discovered.add(normalizedUrl);
          pageInfo.links.push(normalizedUrl);

          if (!visited.has(normalizedUrl)) {
            queue.push({ url: normalizedUrl, depth: depth + 1 });
          }
        }
      });

      // Extract assets
      $('img[src]').each((i, elem) => {
        const src = $(elem).attr('src');
        const normalized = normalizeUrl(src);
        if (normalized) urlMap.assets.images.add(normalized);
      });

      $('script[src]').each((i, elem) => {
        const src = $(elem).attr('src');
        const normalized = normalizeUrl(src);
        if (normalized) urlMap.assets.scripts.add(normalized);
      });

      $('link[rel="stylesheet"]').each((i, elem) => {
        const href = $(elem).attr('href');
        const normalized = normalizeUrl(href);
        if (normalized) urlMap.assets.stylesheets.add(normalized);
      });

      urlMap.pages.push(pageInfo);

    } catch (error) {
      console.error(`[Web Mirror] Error crawling ${url}:`, error.message);
      urlMap.errors.push({
        url,
        depth,
        error: error.message,
        code: error.code
      });
    }

    // Small delay to avoid overwhelming the server
    await new Promise(resolve => setTimeout(resolve, 200));
  }

  console.log(`[Web Mirror] Crawl complete: ${visited.size} pages visited, ${discovered.size} URLs discovered`);

  return {
    startUrl,
    totalPages: visited.size,
    totalDiscovered: discovered.size,
    maxDepthReached: Math.max(...(urlMap.pages.map(p => p.depth).length > 0 ? urlMap.pages.map(p => p.depth) : [0])),
    pages: urlMap.pages,
    assets: {
      images: Array.from(urlMap.assets.images),
      scripts: Array.from(urlMap.assets.scripts),
      stylesheets: Array.from(urlMap.assets.stylesheets),
      totalAssets: urlMap.assets.images.size + urlMap.assets.scripts.size + urlMap.assets.stylesheets.size
    },
    errors: urlMap.errors,
    crawlTime: new Date().toISOString(),
    crawlDuration: Date.now()
  };
}


/* ========== TLS Protocol & Cipher Suite Analysis ========== */

function testTLSVersion(domain, version) {
  return new Promise((resolve) => {
    const options = {
      hostname: domain,
      port: 443,
      method: 'GET',
      path: '/',
      rejectUnauthorized: false,
      minVersion: version,
      maxVersion: version,
    };

    const req = https.request(options, (res) => {
      res.on('data', () => { });
      res.on('end', () => {
        resolve(true);
      });
    });

    req.on('error', () => {
      resolve(false);
    });

    req.setTimeout(5000, () => {
      req.destroy();
      resolve(false);
    });

    req.end();
  });
}

function getCipherSuites(domain) {
  return new Promise((resolve) => {
    const options = {
      hostname: domain,
      port: 443,
      method: 'GET',
      path: '/',
      rejectUnauthorized: false,
    };

    const req = https.request(options, (res) => {
      const cipher = res.socket.getCipher();
      const protocol = res.socket.getProtocol();
      const ephemeralKeyInfo = res.socket.getEphemeralKeyInfo();

      const cipherInfo = {
        ciphers: [
          {
            name: cipher?.name || 'Unknown',
            version: cipher?.version || protocol || 'Unknown',
            bits: cipher?.bits || 0,
          }
        ],
        cipherNames: [cipher?.name || 'Unknown'],
        hasPFS: !!ephemeralKeyInfo,
        weakCiphers: [],
        cbcCiphers: [],
      };

      const weakPatterns = ['DES', 'RC4', 'MD5', 'NULL', 'EXPORT', 'anon'];
      const cbcPattern = /CBC/i;
      const cipherName = cipher?.name || '';

      if (weakPatterns.some(pattern => cipherName.includes(pattern))) {
        cipherInfo.weakCiphers.push(cipherName);
      }

      if (cbcPattern.test(cipherName)) {
        cipherInfo.cbcCiphers.push(cipherName);
      }

      res.on('data', () => { });
      res.on('end', () => {
        resolve(cipherInfo);
      });
    });

    req.on('error', () => {
      resolve({
        ciphers: [],
        cipherNames: [],
        hasPFS: false,
        weakCiphers: [],
        cbcCiphers: [],
      });
    });

    req.setTimeout(5000, () => {
      req.destroy();
      resolve({
        ciphers: [],
        cipherNames: [],
        hasPFS: false,
        weakCiphers: [],
        cbcCiphers: [],
      });
    });

    req.end();
  });
}

function getALPNProtocols(domain) {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host: domain,
      port: 443,
      ALPNProtocols: ['h2', 'http/1.1', 'http/1.0'],
      rejectUnauthorized: false,
      timeout: 5000
    });

    socket.on('secureConnect', () => {
      const protocol = socket.alpnProtocol;
      socket.end();
      resolve(protocol ? [protocol] : []);
    });

    socket.on('error', () => {
      resolve([]);
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve([]);
    });
  });
}

async function analyzeTLSProtocols(domain) {
  const results = {
    protocols: {
      TLSv1: false,
      TLSv1_1: false,
      TLSv1_2: false,
      TLSv1_3: false,
    },
    cipherSuites: [],
    alpnProtocols: [],
    supportedCiphers: [],
    perfectForwardSecrecy: false,
    vulnerabilities: []
  };

  const tlsVersions = [
    { name: 'TLSv1', constant: 'TLSv1_method', severity: 'high' },
    { name: 'TLSv1.1', constant: 'TLSv1_1_method', severity: 'medium' },
    { name: 'TLSv1.2', constant: 'TLSv1_2_method', severity: 'low' },
    { name: 'TLSv1.3', constant: 'TLSv1_3_method', severity: 'info' }
  ];

  for (const version of tlsVersions) {
    try {
      const isSupported = await testTLSVersion(domain, version.name);
      results.protocols[version.name.replace('.', '_')] = isSupported;

      if (isSupported && (version.name === 'TLSv1' || version.name === 'TLSv1.1')) {
        results.vulnerabilities.push({
          type: 'tls_deprecated_protocol',
          severity: version.severity,
          description: `Deprecated ${version.name} Protocol Supported`,
          details: `Server supports ${version.name} which has known security vulnerabilities`,
          recommendation: `Disable ${version.name} and require TLS 1.2 or higher`
        });
      }
    } catch (e) {
      results.protocols[version.name.replace('.', '_')] = false;
    }
  }

  if (!results.protocols.TLSv1_2 && !results.protocols.TLSv1_3) {
    results.vulnerabilities.push({
      type: 'tls_version_weak',
      severity: 'high',
      description: 'TLS Version 1.2 or Higher Not Detected',
      details: 'Server does not support TLS 1.2 or TLS 1.3',
      recommendation: 'Enable TLS 1.2 and TLS 1.3 support'
    });
  }

  try {
    const cipherInfo = await getCipherSuites(domain);
    results.cipherSuites = cipherInfo.ciphers;
    results.supportedCiphers = cipherInfo.cipherNames;
    results.perfectForwardSecrecy = cipherInfo.hasPFS;

    if (cipherInfo.weakCiphers?.length > 0) {
      results.vulnerabilities.push({
        type: 'tls_weak_cipher',
        severity: 'medium',
        description: 'Weak SSL/TLS Cipher Suites Supported',
        details: `Weak ciphers detected: ${cipherInfo.weakCiphers.slice(0, 3).join(', ')}`,
        recommendation: 'Disable weak cipher suites and use only strong ciphers (AES-GCM, ChaCha20)'
      });
    }

    if (cipherInfo.cbcCiphers?.length > 0) {
      results.vulnerabilities.push({
        type: 'tls_cbc_cipher',
        severity: 'low',
        description: 'SSL Cipher Block Chaining (CBC) Cipher Suites Supported',
        details: `CBC mode ciphers detected: ${cipherInfo.cbcCiphers.slice(0, 3).join(', ')}`,
        recommendation: 'Prefer AEAD ciphers (GCM, ChaCha20-Poly1305) over CBC mode ciphers'
      });
    }

    if (!cipherInfo.hasPFS) {
      results.vulnerabilities.push({
        type: 'tls_no_pfs',
        severity: 'medium',
        description: 'SSL Perfect Forward Secrecy Not Supported',
        details: 'No ciphers with Perfect Forward Secrecy (ECDHE/DHE) detected',
        recommendation: 'Enable cipher suites that support Perfect Forward Secrecy (ECDHE-RSA, ECDHE-ECDSA)'
      });
    }
  } catch (e) {
    console.error('Cipher suite analysis error:', e);
  }

  try {
    const alpn = await getALPNProtocols(domain);
    results.alpnProtocols = alpn;
  } catch (e) {
    console.error('ALPN analysis error:', e);
  }

  return results;
}

/* ========== 🆕 NEW FEATURES: CGI, CPE, PostgreSQL Detection ========== */

// 🆕 CGI Generic Injectable Parameter Detection
async function testCGIInjection(domain) {
  const results = {
    tested: false,
    vulnerable: false,
    findings: [],
    errors: []
  };

  const cgiPaths = [
    '/cgi-bin/test.cgi',
    '/cgi-bin/printenv',
    '/cgi-bin/test-cgi',
    '/cgi/test.cgi'
  ];

  const payloads = [
    '?id=1\'',
    '?page=../../etc/passwd',
    '?cmd=ls',
    '?test=<script>alert(1)</script>'
  ];

  try {
    for (const path of cgiPaths) {
      for (const payload of payloads) {
        try {
          const agent = new https.Agent({ rejectUnauthorized: false });
          const response = await axios.get(`https://${domain}${path}${payload}`, {
            timeout: 3000,
            httpsAgent: agent,
            validateStatus: () => true,
            maxRedirects: 0
          });

          results.tested = true;

          if (response.status === 200 && response.data) {
            const data = String(response.data).toLowerCase();
            if (data.includes('error') || data.includes('sql') || data.includes('root:')) {
              results.vulnerable = true;
              results.findings.push({
                path: `${path}${payload}`,
                status: response.status,
                indicator: 'Possible injection vulnerability detected'
              });
            }
          }
        } catch { }
      }
    }
  } catch (error) {
    results.errors.push(error.message);
  }

  return results;
}

// 🆕 Common Platform Enumeration (CPE) Generation
function generateCPE(serverInfo, frameworks, cms) {
  const cpeEntries = [];

  // Generate CPE for server
  if (serverInfo?.type) {
    const serverType = serverInfo.type.toLowerCase();
    const version = serverInfo.version || '*';

    if (serverType.includes('nginx')) {
      cpeEntries.push({
        cpe23: `cpe:2.3:a:nginx:nginx:${version}:*:*:*:*:*:*:*`,
        product: 'nginx',
        vendor: 'nginx',
        version: version
      });
    } else if (serverType.includes('apache')) {
      cpeEntries.push({
        cpe23: `cpe:2.3:a:apache:http_server:${version}:*:*:*:*:*:*:*`,
        product: 'apache_http_server',
        vendor: 'apache',
        version: version
      });
    } else if (serverType.includes('iis')) {
      cpeEntries.push({
        cpe23: `cpe:2.3:a:microsoft:internet_information_services:${version}:*:*:*:*:*:*:*`,
        product: 'iis',
        vendor: 'microsoft',
        version: version
      });
    }
  }

  // Generate CPE for frameworks
  if (frameworks && Array.isArray(frameworks)) {
    for (const fw of frameworks) {
      const fwName = fw.name.toLowerCase();
      const fwVersion = fw.version || '*';

      if (fwName.includes('php')) {
        cpeEntries.push({
          cpe23: `cpe:2.3:a:php:php:${fwVersion}:*:*:*:*:*:*:*`,
          product: 'php',
          vendor: 'php',
          version: fwVersion
        });
      } else if (fwName.includes('next.js')) {
        cpeEntries.push({
          cpe23: `cpe:2.3:a:vercel:next.js:${fwVersion}:*:*:*:*:*:*:*`,
          product: 'next.js',
          vendor: 'vercel',
          version: fwVersion
        });
      }
    }
  }

  // Generate CPE for CMS
  if (cms?.name) {
    const cmsName = cms.name.toLowerCase();
    const cmsVersion = cms.version || '*';

    if (cmsName.includes('wordpress')) {
      cpeEntries.push({
        cpe23: `cpe:2.3:a:wordpress:wordpress:${cmsVersion}:*:*:*:*:*:*:*`,
        product: 'wordpress',
        vendor: 'wordpress',
        version: cmsVersion
      });
    } else if (cmsName.includes('drupal')) {
      cpeEntries.push({
        cpe23: `cpe:2.3:a:drupal:drupal:${cmsVersion}:*:*:*:*:*:*:*`,
        product: 'drupal',
        vendor: 'drupal',
        version: cmsVersion
      });
    }
  }

  return cpeEntries;
}

// 🆕 PostgreSQL Server Detection (Port Scanning)
async function detectPostgreSQL(domain) {
  const results = {
    detected: false,
    port: null,
    version: null,
    starttlsSupported: null
  };

  return new Promise((resolve) => {
    const socket = new net.Socket();
    const timeout = 3000;

    socket.setTimeout(timeout);

    socket.connect(5432, domain, () => {
      results.detected = true;
      results.port = 5432;
      socket.destroy();
      resolve(results);
    });

    socket.on('error', () => {
      socket.destroy();
      resolve(results);
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve(results);
    });
  });
}

// 🆕 Traceroute Implementation
async function performTraceroute(domain) {
  return new Promise((resolve) => {
    try {
      const tracer = new Traceroute();
      const hops = [];
      let completed = false;

      const timeout = setTimeout(() => {
        if (!completed) {
          completed = true;
          tracer.removeAllListeners();
          resolve({
            supported: true,
            hops: hops.length > 0 ? hops : [],
            totalHops: hops.length,
            note: hops.length === 0 ? 'Traceroute completed but no hops recorded' : undefined
          });
        }
      }, 15000); // 15 second timeout

      tracer
        .on('hop', (hop) => {
          if (!completed) {
            hops.push({
              hopNumber: hop.hop,
              ip: hop.ip || '*',
              hostname: hop.name || null,
              rtt1: hop.rtt1,
              rtt2: hop.rtt2,
              rtt3: hop.rtt3
            });
          }
        })
        .on('close', () => {
          if (!completed) {
            completed = true;
            clearTimeout(timeout);
            resolve({
              supported: true,
              hops,
              totalHops: hops.length
            });
          }
        })
        .on('error', (error) => {
          if (!completed) {
            completed = true;
            clearTimeout(timeout);
            resolve({
              supported: false,
              error: error.message,
              note: 'Traceroute failed or not available'
            });
          }
        });

      tracer.trace(domain);
    } catch (error) {
      resolve({
        supported: false,
        error: error.message,
        note: 'Traceroute not supported on this system'
      });
    }
  });
}

// 🆕 Network Timing Analysis (Alternative to TCP Timestamps)
async function measureNetworkTimings(domain) {
  const timings = {
    dnsLookup: null,
    tcpConnection: null,
    tlsHandshake: null,
    ttfb: null, // Time to first byte
    totalTime: null,
    measurements: []
  };

  return new Promise((resolve) => {
    const start = process.hrtime.bigint();
    let dnsTime = null;
    let tcpTime = null;
    let tlsTime = null;

    const req = https.request(`https://${domain}`, (res) => {
      const ttfbTime = process.hrtime.bigint();
      timings.ttfb = Number(ttfbTime - start) / 1000000; // Convert to ms

      res.once('readable', () => {
        // First byte received
      });

      res.on('end', () => {
        const end = process.hrtime.bigint();
        timings.totalTime = Number(end - start) / 1000000;

        timings.dnsLookup = dnsTime;
        timings.tcpConnection = tcpTime;
        timings.tlsHandshake = tlsTime;

        resolve({
          supported: true,
          timings
        });
      });

      res.on('error', () => {
        resolve({
          supported: false,
          error: 'Response error'
        });
      });
    });

    req.on('socket', (socket) => {
      socket.on('lookup', () => {
        const lookupTime = process.hrtime.bigint();
        dnsTime = Number(lookupTime - start) / 1000000;
      });

      socket.on('connect', () => {
        const connectTime = process.hrtime.bigint();
        tcpTime = Number(connectTime - start) / 1000000;
      });

      socket.on('secureConnect', () => {
        const secureTime = process.hrtime.bigint();
        tlsTime = Number(secureTime - start) / 1000000;
      });
    });

    req.on('error', (error) => {
      resolve({
        supported: false,
        error: error.message
      });
    });

    req.setTimeout(20000, () => {
      req.destroy();
      resolve({
        supported: false,
        error: 'Connection timeout'
      });
    });

    req.end();
  });
}

/* ========== Existing Service Detection (Extended) ========== */

async function resolveHostFQDN(domain) {
  try {
    const addresses = await resolve4Async(domain);
    const reverseDns = [];

    for (const ip of addresses.slice(0, 3)) {
      try {
        const hostnames = await reverseAsync(ip);
        reverseDns.push({ ip, hostnames });
      } catch (e) {
        reverseDns.push({ ip, hostnames: [] });
      }
    }

    return {
      ipv4Addresses: addresses,
      reverseDns,
      fqdn: reverseDns[0]?.hostnames[0] || domain
    };
  } catch (error) {
    return {
      error: error.message,
      ipv4Addresses: [],
      reverseDns: [],
      fqdn: domain
    };
  }
}

async function check404Handling(domain) {
  try {
    const randomPath = `/nonexistent-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const agent = new https.Agent({ rejectUnauthorized: false });

    const response = await axios.get(`https://${domain}${randomPath}`, {
      timeout: 5000,
      httpsAgent: agent,
      validateStatus: () => true,
    });

    return {
      statusCode: response.status,
      properlyConfigured: response.status === 404,
    };
  } catch (error) {
    return {
      error: error.message,
      properlyConfigured: false,
    };
  }
}

function extractExternalURLs(html, currentDomain) {
  const externalUrls = new Set();

  if (!html) return [];

  const $ = cheerio.load(html);

  $('a[href], link[href], script[src], img[src], iframe[src]').each((_, element) => {
    const url = $(element).attr('href') || $(element).attr('src');

    if (url && /^https?:\/\//i.test(url)) {
      try {
        const urlObj = new URL(url);
        if (urlObj.hostname !== currentDomain && !urlObj.hostname.endsWith(`.${currentDomain}`)) {
          externalUrls.add(urlObj.origin);
        }
      } catch (e) { }
    }
  });

  return Array.from(externalUrls).slice(0, 50);
}

/* ========== COMPLETE Service Detection with NEW features ========== */

async function detectServiceTechnology(domain, headers, htmlBody) {
  const detections = {
    serverInfo: {
      type: null,
      version: null,
      os: null,
      confidence: 'low'
    },
    frameworks: [],
    technologies: [],
    cms: null,
    applicationServers: [],
    databases: [],
    deviceType: 'server',
    httpInfo: {
      methods: [],
      features: []
    },
    cpe: [],
    cgiTesting: null,
    postgresqlDetection: null
  };

  // Parse Server Header
  if (headers.server) {
    const serverHeader = headers.server;
    detections.serverInfo.type = serverHeader;

    const versionMatch = serverHeader.match(/\/([\d.]+)/);
    if (versionMatch) {
      detections.serverInfo.version = versionMatch[1];
    }

    if (/ubuntu|debian|centos|redhat|fedora/i.test(serverHeader)) {
      const osMatch = serverHeader.match(/(ubuntu|debian|centos|redhat|fedora)/i);
      if (osMatch) {
        detections.serverInfo.os = osMatch[1];
      }
    }

    if (/tomcat|apache-coyote/i.test(serverHeader)) {
      detections.applicationServers.push({
        name: 'Apache Tomcat',
        detected: 'server-header',
        confidence: 'high'
      });
    }

    if (/jetty/i.test(serverHeader)) {
      detections.applicationServers.push({
        name: 'Jetty',
        detected: 'server-header',
        confidence: 'high'
      });
    }

    if (/glassfish/i.test(serverHeader)) {
      detections.applicationServers.push({
        name: 'GlassFish',
        detected: 'server-header',
        confidence: 'high'
      });
    }

    if (/websphere/i.test(serverHeader)) {
      detections.applicationServers.push({
        name: 'IBM WebSphere',
        detected: 'server-header',
        confidence: 'high'
      });
    }

    if (/weblogic/i.test(serverHeader)) {
      detections.applicationServers.push({
        name: 'Oracle WebLogic',
        detected: 'server-header',
        confidence: 'high'
      });
    }
  }

  // Framework Detection from Headers
  if (headers['x-powered-by']) {
    const poweredBy = headers['x-powered-by'];

    if (/php/i.test(poweredBy)) {
      detections.frameworks.push({
        name: 'PHP',
        version: poweredBy.match(/PHP\/([\d.]+)/i)?.[1] || 'unknown',
        detected: 'x-powered-by',
        confidence: 'high'
      });
    }

    if (/asp\.net/i.test(poweredBy)) {
      detections.frameworks.push({
        name: 'ASP.NET',
        version: poweredBy.match(/ASP\.NET\/([\d.]+)/i)?.[1] || 'unknown',
        detected: 'x-powered-by',
        confidence: 'high'
      });
    }

    if (/express/i.test(poweredBy)) {
      detections.frameworks.push({
        name: 'Express.js',
        detected: 'x-powered-by',
        confidence: 'high'
      });
    }
  }

  if (headers['x-nextjs-cache'] || headers['x-nextjs-page']) {
    detections.frameworks.push({
      name: 'Next.js',
      detected: 'headers',
      confidence: 'high'
    });
  }

  if (headers['x-vercel-id'] || headers['x-vercel-cache']) {
    detections.technologies.push({
      name: 'Vercel',
      type: 'hosting',
      detected: 'headers',
      confidence: 'high'
    });
  }

  if (headers['cf-ray'] || headers['cf-cache-status']) {
    detections.technologies.push({
      name: 'Cloudflare',
      type: 'cdn',
      detected: 'headers',
      confidence: 'high'
    });
  }

  // HTML-based detection
  if (htmlBody) {
    if (/wp-content|wp-includes|wordpress/i.test(htmlBody)) {
      detections.cms = {
        name: 'WordPress',
        detected: 'html-content',
        confidence: 'high'
      };

      const wpVersionMatch = htmlBody.match(/wp-content\/themes\/[^\/]+\/([\d.]+)/);
      if (wpVersionMatch) {
        detections.cms.version = wpVersionMatch[1];
      }
    }

    if (/drupal/i.test(htmlBody)) {
      detections.cms = {
        name: 'Drupal',
        detected: 'html-content',
        confidence: 'medium'
      };
    }

    if (/joomla/i.test(htmlBody)) {
      detections.cms = {
        name: 'Joomla',
        detected: 'html-content',
        confidence: 'medium'
      };
    }

    if (/__REACT|react-root|reactroot/i.test(htmlBody)) {
      detections.frameworks.push({
        name: 'React',
        detected: 'html-content',
        confidence: 'medium'
      });
    }

    if (/vue|v-app|v-bind/i.test(htmlBody)) {
      detections.frameworks.push({
        name: 'Vue.js',
        detected: 'html-content',
        confidence: 'medium'
      });
    }

    if (/ng-version|angular/i.test(htmlBody)) {
      detections.frameworks.push({
        name: 'Angular',
        detected: 'html-content',
        confidence: 'medium'
      });
    }

    if (/jquery/i.test(htmlBody)) {
      detections.technologies.push({
        name: 'jQuery',
        type: 'library',
        detected: 'html-content',
        confidence: 'medium'
      });
    }

    if (/bootstrap/i.test(htmlBody)) {
      detections.technologies.push({
        name: 'Bootstrap',
        type: 'css-framework',
        detected: 'html-content',
        confidence: 'medium'
      });
    }

    if (/tailwind/i.test(htmlBody)) {
      detections.technologies.push({
        name: 'Tailwind CSS',
        type: 'css-framework',
        detected: 'html-content',
        confidence: 'medium'
      });
    }
  }

  detections.httpInfo = {
    version: headers.httpVersion || '1.1',
    statusCode: headers.statusCode,
    statusMessage: headers.statusMessage,
    features: []
  };

  if (headers.httpVersion === '2.0' || headers.httpVersion === '2') {
    detections.httpInfo.features.push('HTTP/2');
  }

  if (headers['alt-svc'] && /h3/i.test(headers['alt-svc'])) {
    detections.httpInfo.features.push('HTTP/3 Support');
  }

  if (headers['content-encoding']) {
    detections.httpInfo.features.push(`Compression: ${headers['content-encoding']}`);
  } else if (headers.rawHeaders && Array.isArray(headers.rawHeaders)) {
    const idx = headers.rawHeaders.findIndex(h =>
      typeof h === 'string' && h.toLowerCase() === 'content-encoding'
    );
    if (idx !== -1 && headers.rawHeaders[idx + 1]) {
      detections.httpInfo.features.push(`Compression: ${headers.rawHeaders[idx + 1]}`);
    }
  }

  // 🆕 Generate CPE entries
  detections.cpe = generateCPE(detections.serverInfo, detections.frameworks, detections.cms);

  // 🆕 Test CGI vulnerabilities
  try {
    detections.cgiTesting = await testCGIInjection(domain);
  } catch (error) {
    console.error('CGI testing error:', error);
    detections.cgiTesting = { tested: false, error: error.message };
  }

  // 🆕 Detect PostgreSQL
  try {
    detections.postgresqlDetection = await detectPostgreSQL(domain);
  } catch (error) {
    console.error('PostgreSQL detection error:', error);
    detections.postgresqlDetection = { detected: false, error: error.message };
  }
  // 🆕 NEW: Traceroute
  try {
    detections.traceroute = await performTraceroute(domain);
  } catch (error) {
    console.error('Traceroute error:', error);
    detections.traceroute = { supported: false, error: error.message };
  }

  // 🆕 NEW: Network Timings
  try {
    detections.networkTimings = await measureNetworkTimings(domain);
  } catch (error) {
    console.error('Network timings error:', error);
    detections.networkTimings = { supported: false, error: error.message };
  }
  return detections;
}

/* ========== MAIN SCAN FUNCTION WITH NEW FEATURES ========== */

export const runScan = async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required.' });

  try {
    const domain = url.replace(/^https?:\/\//, '').split('/')[0];
    const formattedUrl = `https://${domain}`;

    const scanResults = {
      domain,
      timestamp: new Date().toISOString(),
      scannerVersion: '1.0.0',
      scanId: `scan_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      ssl: null,
      headers: null,
      serviceDetection: null,
      openPorts: null,
      vulnerabilities: [],
      vulnerabilityCount: 0,
      vulnerabilityBreakdown: null,
      riskLevel: 'low',
      securityGrade: null,
      timespan: 0,
      sitemap: null,
      robots: null,
      htmlAnalysis: null,
      errorHandling: { check404: null },
    };

    // 1) SSL/TLS Certificate Checks (ALL YOUR EXISTING CODE - UNCHANGED)
    try {
      const sslInfo = await sslChecker(domain);
      scanResults.ssl = sslInfo;

      if (sslInfo.valid) {
        try {
          const isSelfSigned = sslInfo.issuer &&
            (sslInfo.issuer === domain ||
              sslInfo.issuer.toLowerCase().includes(domain.toLowerCase()));

          if (isSelfSigned) {
            scanResults.vulnerabilities.push({
              type: 'ssl_self_signed',
              severity: 'high',
              description: 'SSL Self-Signed Certificate',
              details: `Certificate appears to be self-signed. Issuer: ${sslInfo.issuer}`,
              recommendation: 'Use a certificate from a trusted Certificate Authority (CA) like Let\'s Encrypt, DigiCert, or Comodo'
            });
          }
        } catch (e) {
          console.error('Self-signed check error:', e);
        }
      }

      if (!sslInfo.valid) {
        scanResults.vulnerabilities.push({
          type: 'ssl_hostname_mismatch',
          severity: 'high',
          description: 'SSL Certificate with Wrong Hostname',
          details: `Certificate hostname does not match domain: ${domain}`,
          recommendation: 'Obtain a certificate that matches your domain name or includes it in Subject Alternative Names (SAN)'
        });
      }

      if (!sslInfo.valid) {
        scanResults.vulnerabilities.push({
          type: 'ssl_untrusted',
          severity: 'critical',
          description: 'SSL Certificate Cannot Be Trusted',
          details: `Certificate validation failed for ${domain}. This could indicate an untrusted CA, expired certificate, or invalid certificate chain.`,
          recommendation: 'Ensure certificate is issued by a trusted CA and the certificate chain is complete'
        });
      }

      if (sslInfo.valid && sslInfo.daysRemaining <= 30 && sslInfo.daysRemaining > 0) {
        scanResults.vulnerabilities.push({
          type: 'ssl_expiring_soon',
          severity: 'medium',
          description: 'SSL Certificate Expiring Soon',
          details: `Certificate expires in ${sslInfo.daysRemaining} days (Valid until: ${sslInfo.validTo})`,
          recommendation: 'Renew certificate before expiration to avoid service disruption. Consider using automated renewal with Let\'s Encrypt or your CA\'s auto-renewal service'
        });
      }

      if (sslInfo.daysRemaining < 0) {
        scanResults.vulnerabilities.push({
          type: 'ssl_expired',
          severity: 'critical',
          description: 'SSL Certificate Expired',
          details: `Certificate expired ${Math.abs(sslInfo.daysRemaining)} days ago (Valid until: ${sslInfo.validTo})`,
          recommendation: 'Renew certificate immediately. Expired certificates cause browser warnings and security risks'
        });
      }

      // Certificate Chain (ALL YOUR EXISTING CODE)
      try {
        const checkCertChain = () => {
          return new Promise((resolve, reject) => {
            const options = {
              hostname: domain,
              port: 443,
              path: '/',
              method: 'GET',
              rejectUnauthorized: false,
              agent: false
            };

            const req = https.request(options, (res) => {
              const cert = res.socket.getPeerCertificate(true);
              const chain = [];

              let currentCert = cert;
              while (currentCert && Object.keys(currentCert).length > 0) {
                if (currentCert.issuerCertificate &&
                  currentCert.issuerCertificate !== currentCert) {
                  chain.push({
                    subject: currentCert.subject?.CN || 'Unknown',
                    issuer: currentCert.issuer?.CN || 'Unknown',
                    validFrom: currentCert.valid_from,
                    validTo: currentCert.valid_to,
                  });
                  currentCert = currentCert.issuerCertificate;
                } else {
                  chain.push({
                    subject: currentCert.subject?.CN || 'Unknown',
                    issuer: currentCert.issuer?.CN || 'Unknown',
                    validFrom: currentCert.valid_from,
                    validTo: currentCert.valid_to,
                    isRoot: true
                  });
                  break;
                }
              }

              resolve(chain);
            });

            req.on('error', (e) => {
              reject(e);
            });

            req.end();
          });
        };

        const certChain = await checkCertChain();

        scanResults.ssl.certificateChain = certChain;
        scanResults.ssl.chainLength = certChain.length;

        const rootCert = certChain.find(c => c.isRoot);
        if (rootCert) {
          scanResults.ssl.rootCA = {
            subject: rootCert.subject,
            issuer: rootCert.issuer,
            validFrom: rootCert.validFrom,
            validTo: rootCert.validTo
          };
        }

        const expiringChainCerts = certChain.filter(cert => {
          if (!cert.validTo) return false;
          const expiryDate = new Date(cert.validTo);
          const now = new Date();
          const daysRemaining = Math.floor((expiryDate - now) / (1000 * 60 * 60 * 24));
          return daysRemaining <= 30 && daysRemaining > 0;
        });

        if (expiringChainCerts.length > 0) {
          scanResults.vulnerabilities.push({
            type: 'ssl_chain_expiring',
            severity: 'medium',
            description: 'SSL Certificate Chain Contains Certificates Expiring Soon',
            details: `${expiringChainCerts.length} certificate(s) in the chain will expire within 30 days: ${expiringChainCerts.map(c => c.subject).join(', ')}`,
            recommendation: 'Renew intermediate or root certificates in the chain to maintain trust'
          });
        }

      } catch (chainError) {
        console.error('Certificate chain check error:', chainError);
        scanResults.ssl.certificateChain = null;
        scanResults.ssl.chainCheckError = chainError.message;
      }

      // TLS Protocol & Cipher Suite Support
      try {
        const tlsAnalysis = await analyzeTLSProtocols(domain);
        scanResults.ssl.tlsProtocols = tlsAnalysis.protocols;
        scanResults.ssl.cipherSuites = tlsAnalysis.cipherSuites;
        scanResults.ssl.alpnProtocols = tlsAnalysis.alpnProtocols;
        scanResults.ssl.perfectForwardSecrecy = tlsAnalysis.perfectForwardSecrecy;

        if (tlsAnalysis.vulnerabilities?.length > 0) {
          scanResults.vulnerabilities.push(...tlsAnalysis.vulnerabilities);
        }

      } catch (tlsError) {
        console.error('TLS protocol analysis error:', tlsError);
        scanResults.ssl.tlsProtocols = null;
        scanResults.ssl.tlsCheckError = tlsError.message;
      }

    } catch (error) {
      console.error('SSL check error:', error);

      scanResults.ssl = {
        valid: false,
        error: error.message,
        daysRemaining: null
      };

      scanResults.vulnerabilities.push({
        type: 'ssl_error',
        severity: 'high',
        description: 'SSL certificate issue detected',
        details: error.message,
        recommendation: 'Verify SSL/TLS configuration. Common issues: expired certificate, wrong hostname, untrusted CA, or incomplete certificate chain'
      });
    }

    // 2) HTTP headers (ALL YOUR EXISTING CODE - UNCHANGED)
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
        scanResults.headers.rawHeaders = nodeRes.rawHeaders;
        scanResults.headers.httpVersion = nodeRes.httpVersion || '';
        scanResults.headers.statusCode = nodeRes.statusCode;
        scanResults.headers.statusMessage = nodeRes.statusMessage || '';
      } else {
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

      if (headers.server) {
        scanResults.vulnerabilities.push({
          type: 'information_disclosure',
          severity: 'low',
          description: 'Server information disclosure',
          details: `Server header reveals: ${headers.server}`,
          recommendation: 'Avoid exposing server brand/version'
        });
      }

      const cookieFindings = parseSetCookie(headers['set-cookie']);
      scanResults.headers.cookieFindings = cookieFindings.length > 0 ? cookieFindings : [];

      const pageIsHttps = /^https:\/\//i.test(formattedUrl);
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

        if (pageIsHttps && !c.flags.includes('Secure')) {
          scanResults.vulnerabilities.push({
            type: 'cookie_secure_mismatch',
            severity: 'medium',
            description: 'HTTP Cookie \'secure\' Property Transport Mismatch',
            details: `Cookie "${c.name}" transmitted over HTTPS without Secure flag`,
            recommendation: 'Set the Secure flag on all cookies transmitted over HTTPS'
          });
        }
      }

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

      try {
        const agentFollow = new https.Agent({ rejectUnauthorized: false });
        const htmlResp = await axios.get(formattedUrl, {
          timeout: 8000,
          httpsAgent: agentFollow,
          validateStatus: () => true,
          maxRedirects: 5,
          responseType: 'text',
          transformResponse: [(d) => d]
        });
        htmlBody = typeof htmlResp.data === 'string' ? htmlResp.data : '';
        finalUrlUsed = htmlResp.request?.res?.responseUrl || formattedUrl;
      } catch { }

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

      // Service Detection with NEW features
      try {
        const serviceDetection = await detectServiceTechnology(
          domain,
          scanResults.headers || {},
          htmlBody
        );

        scanResults.serviceDetection = serviceDetection;

        try {
          const fqdnInfo = await resolveHostFQDN(domain);
          scanResults.serviceDetection.fqdnInfo = fqdnInfo;
        } catch (fqdnError) {
          console.error('FQDN resolution error:', fqdnError);
        }

        // 🆕 Add CGI vulnerabilities if found
        if (serviceDetection.cgiTesting?.vulnerable) {
          scanResults.vulnerabilities.push({
            type: 'cgi_injectable',
            severity: 'high',
            description: 'CGI Generic Injectable Parameter',
            details: `Possible CGI injection vulnerability detected: ${serviceDetection.cgiTesting.findings.length} finding(s)`,
            recommendation: 'Review and sanitize all CGI script inputs. Consider disabling CGI if not needed.'
          });
        }

        if (serviceDetection.cgiTesting?.tested) {
          scanResults.vulnerabilities.push({
            type: 'cgi_tested',
            severity: 'info',
            description: 'CGI Generic Tests Completed',
            details: `CGI endpoints tested. Vulnerable: ${serviceDetection.cgiTesting.vulnerable ? 'Yes' : 'No'}`,
            recommendation: 'Regular CGI security testing recommended'
          });
        }

        // 🆕 Add PostgreSQL detection results
        if (serviceDetection.postgresqlDetection?.detected) {
          scanResults.vulnerabilities.push({
            type: 'postgresql_detected',
            severity: 'info',
            description: 'PostgreSQL Server Detection',
            details: `PostgreSQL detected on port ${serviceDetection.postgresqlDetection.port}`,
            recommendation: 'Ensure PostgreSQL is properly secured and not publicly accessible unless necessary'
          });
        }

        // 🆕 Add CPE information as informational finding
        if (serviceDetection.cpe?.length > 0) {
          scanResults.vulnerabilities.push({
            type: 'cpe_enumeration',
            severity: 'info',
            description: 'Common Platform Enumeration (CPE)',
            details: `Identified ${serviceDetection.cpe.length} CPE entr(ies): ${serviceDetection.cpe.map(c => c.product).join(', ')}`,
            recommendation: 'Monitor CVE databases for vulnerabilities related to identified platforms'
          });
        }

        // 🆕 NEW: Add Traceroute information
        if (serviceDetection.traceroute?.supported && serviceDetection.traceroute.hops?.length > 0) {
          scanResults.vulnerabilities.push({
            type: 'traceroute_info',
            severity: 'info',
            description: 'Traceroute Information',
            details: `Network path traced: ${serviceDetection.traceroute.totalHops} hops detected`,
            recommendation: 'Review network path for security and performance optimization'
          });
        }

        // 🆕 NEW: Add Network Timing information
        if (serviceDetection.networkTimings?.supported) {
          const timings = serviceDetection.networkTimings.timings;
          scanResults.vulnerabilities.push({
            type: 'network_timings',
            severity: 'info',
            description: 'TCP/IP Network Timings',
            details: `DNS: ${timings.dnsLookup?.toFixed(2)}ms, TCP: ${timings.tcpConnection?.toFixed(2)}ms, TLS: ${timings.tlsHandshake?.toFixed(2)}ms, TTFB: ${timings.ttfb?.toFixed(2)}ms`,
            recommendation: 'Monitor network performance for optimization opportunities'
          });
        }

        if (serviceDetection.applicationServers.length > 0) {
          serviceDetection.applicationServers.forEach(server => {
            scanResults.vulnerabilities.push({
              type: 'service_detection',
              severity: 'info',
              description: `${server.name} Detected`,
              details: `Application server detected via ${server.detected}`,
              recommendation: 'Ensure server is up-to-date and properly configured'
            });
          });
        }

        const tomcatDetected = serviceDetection.applicationServers.find(
          s => s.name === 'Apache Tomcat'
        );

        if (tomcatDetected) {
          scanResults.vulnerabilities.push({
            type: 'tomcat_detection',
            severity: 'info',
            description: 'Apache Tomcat Application Server Detected',
            details: 'Apache Tomcat is running on this server',
            recommendation: 'Keep Tomcat updated and disable default management interfaces'
          });
        }

        if (serviceDetection.cms) {
          scanResults.vulnerabilities.push({
            type: 'cms_detection',
            severity: 'info',
            description: `${serviceDetection.cms.name} CMS Detected`,
            details: `Content Management System: ${serviceDetection.cms.name}`,
            recommendation: `Keep ${serviceDetection.cms.name} and plugins updated`
          });
        }

      } catch (serviceError) {
        console.error('Service detection error:', serviceError);
        scanResults.serviceDetection = {
          error: serviceError.message
        };
      }

    } catch (error) {
      console.error('HTTP headers error:', error);
      scanResults.vulnerabilities.push({
        type: 'connection',
        severity: 'medium',
        description: 'Failed to connect or retrieve headers',
        details: error.message,
        recommendation: 'Ensure HTTPS is reachable and not blocking scanners'
      });
    }

    // HTML Form Analysis (ALL YOUR EXISTING CODE)
    if (htmlBody) {
      try {
        const formAnalysis = analyzeHTMLForms(htmlBody, finalUrlUsed);
        scanResults.htmlAnalysis = formAnalysis;

        if (formAnalysis.autoCompleteIssues.length > 0) {
          scanResults.vulnerabilities.push({
            type: 'form_autocomplete',
            severity: 'medium',
            description: 'Web Server Allows Password Auto-Completion',
            details: `${formAnalysis.autoCompleteIssues.length} password field(s) allow autocomplete: ${formAnalysis.autoCompleteIssues[0]}`,
            recommendation: 'Set autocomplete="off" or use "current-password"/"new-password" values for password fields'
          });
        }

        if (formAnalysis.cleartextCredentials) {
          scanResults.vulnerabilities.push({
            type: 'cleartext_credentials',
            severity: 'critical',
            description: 'Web Server Transmits Cleartext Credentials',
            details: 'Form with password field submits to HTTP (unencrypted) endpoint',
            recommendation: 'Use HTTPS for all forms transmitting sensitive data, especially passwords'
          });
        }

        if (formAnalysis.insecureActions.length > 0) {
          scanResults.vulnerabilities.push({
            type: 'insecure_form_action',
            severity: 'high',
            description: 'Forms Submit to Insecure HTTP Endpoints',
            details: `${formAnalysis.insecureActions.length} form(s) use HTTP actions: ${formAnalysis.insecureActions.slice(0, 3).join(', ')}`,
            recommendation: 'Change all form actions to use HTTPS'
          });
        }
      } catch (formError) {
        console.error('HTML form analysis error:', formError);
      }

      try {
        const externalUrls = extractExternalURLs(htmlBody, domain);
        if (scanResults.serviceDetection) {
          scanResults.serviceDetection.externalUrls = externalUrls;
        }
      } catch (urlError) {
        console.error('External URL extraction error:', urlError);
      }
    }

    // Robots.txt, Sitemap, 404 Check (ALL YOUR EXISTING CODE)
    try {
      const agent = new https.Agent({ rejectUnauthorized: false });
      const robotsResp = await axios.get(`https://${domain}/robots.txt`, {
        timeout: 5000,
        httpsAgent: agent,
        validateStatus: () => true,
      });

      if (robotsResp.status === 200 && robotsResp.data) {
        const robotsAnalysis = analyzeRobotsTxt(robotsResp.data);
        scanResults.robots = robotsAnalysis;

        if (robotsAnalysis.sitemaps.length > 0) {
          scanResults.vulnerabilities.push({
            type: 'robots_sitemap',
            severity: 'info',
            description: 'Sitemaps Declared in robots.txt',
            details: `Found ${robotsAnalysis.sitemaps.length} sitemap(s): ${robotsAnalysis.sitemaps.slice(0, 3).join(', ')}`,
            recommendation: 'Ensure sitemaps are up-to-date and don\'t expose sensitive URLs'
          });
        }
      } else {
        scanResults.robots = { present: false, allowsAll: true, disallowRules: [], sitemaps: [] };
      }
    } catch (robotsError) {
      console.error('Robots.txt fetch error:', robotsError);
      scanResults.robots = { present: false, error: robotsError.message, allowsAll: true, disallowRules: [], sitemaps: [] };
    }

    // 🆕 WEB MIRRORING (NEW FEATURE - ADD THIS)
    console.log('[Scanner] Starting web mirroring...');
    try {
      const webMirror = await crawlWebsite(formattedUrl, {
        maxPages: 50,
        maxDepth: 3,
        timeout: 15000,
        onlySubdomain: true
      });

      scanResults.webMirror = webMirror;
      console.log(`[Scanner] Web mirror complete: ${webMirror.totalPages} pages found`);

      // Add vulnerability entry
      scanResults.vulnerabilities.push({
        type: 'web_mirror',
        severity: 'info',
        description: 'Web Application Structure Mapped',
        details: `Discovered ${webMirror.totalPages} pages, ${webMirror.totalDiscovered} unique URLs, ${webMirror.assets.totalAssets} assets`,
        recommendation: 'Review exposed pages and ensure sensitive pages are properly protected'
      });

      // Check for potential sensitive pages
      const sensitivePaths = ['/admin', '/login', '/dashboard', '/api', '/config', '/backup', '/.git', '/.env'];
      const exposedSensitive = webMirror.pages.filter(page =>
        sensitivePaths.some(path => page.url.toLowerCase().includes(path))
      );

      if (exposedSensitive.length > 0) {
        scanResults.vulnerabilities.push({
          type: 'sensitive_paths_exposed',
          severity: 'medium',
          description: 'Potentially Sensitive Paths Discovered',
          details: `Found ${exposedSensitive.length} potentially sensitive URL(s): ${exposedSensitive.slice(0, 3).map(p => p.url).join(', ')}`,
          recommendation: 'Ensure sensitive paths are properly secured with authentication and access controls'
        });
      }

    } catch (mirrorError) {
      console.error('[Scanner] Web mirroring failed:', mirrorError.message);
      scanResults.webMirror = {
        error: mirrorError.message,
        totalPages: 0,
        pages: []
      };
    }

    // Vulnerability breakdown, risk, grade (EXISTING CODE CONTINUES HERE)
    // const vulnBreakdown = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };


    try {
      const agent = new https.Agent({ rejectUnauthorized: false });
      const sitemapUrls = [
        `https://${domain}/sitemap.xml`,
        `https://${domain}/sitemap_index.xml`,
        ...(scanResults.robots?.sitemaps || [])
      ];

      let sitemapFound = false;
      for (const sitemapUrl of sitemapUrls) {
        try {
          const sitemapResp = await axios.get(sitemapUrl, {
            timeout: 5000,
            httpsAgent: agent,
            validateStatus: () => true,
          });

          if (sitemapResp.status === 200 && sitemapResp.data) {
            const sitemapSummary = await summarizeSitemap(sitemapResp.data);
            scanResults.sitemap = {
              url: sitemapUrl,
              ...sitemapSummary
            };

            scanResults.vulnerabilities.push({
              type: 'sitemap_found',
              severity: 'info',
              description: 'Web Application Sitemap',
              details: `Sitemap found at ${sitemapUrl}: ${sitemapSummary.type}, ${sitemapSummary.totalUrls || sitemapSummary.totalSitemaps || 0} entries`,
              recommendation: 'Ensure sitemap doesn\'t expose sensitive or administrative URLs'
            });

            sitemapFound = true;
            break;
          }
        } catch {
          continue;
        }
      }

      if (!sitemapFound) {
        scanResults.sitemap = { present: false };
      }
    } catch (sitemapError) {
      console.error('Sitemap fetch error:', sitemapError);
      scanResults.sitemap = { present: false, error: sitemapError.message };
    }

    try {
      const check404 = await check404Handling(domain);
      scanResults.errorHandling.check404 = check404;

      if (!check404.properlyConfigured) {
        scanResults.vulnerabilities.push({
          type: '404_misconfigured',
          severity: 'low',
          description: 'Web Server No 404 Error Code Check',
          details: `Server returned status ${check404.statusCode} instead of 404 for non-existent page`,
          recommendation: 'Configure server to return proper 404 status codes for non-existent resources'
        });
      }
    } catch (check404Error) {
      console.error('404 check error:', check404Error);
    }

    // Vulnerability breakdown, risk, grade (ALL YOUR EXISTING CODE)
    const vulnBreakdown = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    scanResults.vulnerabilities.forEach(v => {
      if (vulnBreakdown[v.severity] !== undefined) vulnBreakdown[v.severity]++;
    });
    scanResults.vulnerabilityBreakdown = vulnBreakdown;

    scanResults.vulnerabilityCount = scanResults.vulnerabilities.length;

    if (vulnBreakdown.critical > 0) {
      scanResults.riskLevel = 'critical';
    } else if (vulnBreakdown.high > 2 || (vulnBreakdown.high > 0 && vulnBreakdown.medium > 3)) {
      scanResults.riskLevel = 'high';
    } else if (vulnBreakdown.high > 0 || vulnBreakdown.medium > 2) {
      scanResults.riskLevel = 'medium';
    } else {
      scanResults.riskLevel = 'low';
    }

    const metrics = {
      vulnCount: scanResults.vulnerabilityCount || 0,
      missingSecHeaders: countMissingSecurityHeaders(scanResults.headers || {}),
      weakCookies: (scanResults.headers?.cookieFindings?.filter(c => c.issues.length > 0).length) || 0,
      cspIssues: (scanResults.headers?.csp?.issues?.length) || 0
    };
    scanResults.metrics = metrics;
    scanResults.securityGrade = gradeFromMetrics(metrics);

    const saved = await ScanResult.create(scanResults);
    return res.status(200).json(saved);

  } catch (error) {
    console.error('Scan error:', error);
    return res.status(500).json({
      error: 'Failed to complete scan',
      message: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
};


export const getHistory = async (req, res) => {
  const { domain, limit = 10 } = req.query;
  if (!domain) return res.status(400).json({ error: 'domain is required' });

  const rows = await ScanResult.find({ domain })
    .select('domain timestamp vulnerabilityCount riskLevel timespan headers._benchmark.grade ssl.valid')
    .sort({ timestamp: -1 })
    .limit(Math.min(Number(limit) || 10, 50));

  res.json({ domain, count: rows.length, items: rows });
};
