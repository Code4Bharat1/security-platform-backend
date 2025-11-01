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

    // ✅ PHASE 1: RUN INITIAL CHECKS IN PARALLEL (5-8 seconds)
    console.log('[Scanner] Phase 1: SSL, Headers, Robots - Starting...');
    const [sslResult, headersResult, robotsResult] = await Promise.allSettled([
      // SSL Check
      sslChecker(domain).catch(err => ({ valid: false, error: err.message })),

      // Headers Check
      (async () => {
        const agent = new https.Agent({ rejectUnauthorized: false });
        const started = Date.now();
        const response = await axios.get(formattedUrl, {
          timeout: 6000, // ✅ Reduced from 8000
          httpsAgent: agent,
          validateStatus: () => true,
          maxRedirects: 0
        });
        return { response, timespan: Date.now() - started };
      })(),

      // Robots.txt Check
      (async () => {
        const agent = new https.Agent({ rejectUnauthorized: false });
        const resp = await axios.get(`https://${domain}/robots.txt`, {
          timeout: 3000, // ✅ Reduced from 5000
          httpsAgent: agent,
          validateStatus: () => true,
        });
        if (resp.status === 200 && resp.data) {
          return analyzeRobotsTxt(resp.data);
        }
        return { present: false, allowsAll: true, disallowRules: [], sitemaps: [] };
      })()
    ]);

    // Process SSL results (unchanged)
    if (sslResult.status === 'fulfilled') {
      scanResults.ssl = sslResult.value;

      if (sslResult.value.valid) {
        try {
          const isSelfSigned = sslResult.value.issuer &&
            (sslResult.value.issuer === domain ||
              sslResult.value.issuer.toLowerCase().includes(domain.toLowerCase()));

          if (isSelfSigned) {
            scanResults.vulnerabilities.push({
              type: 'ssl_self_signed',
              severity: 'high',
              description: 'SSL Self-Signed Certificate',
              details: `Certificate appears to be self-signed. Issuer: ${sslResult.value.issuer}`,
              recommendation: 'Use a certificate from a trusted Certificate Authority (CA)'
            });
          }
        } catch (e) { }
      }

      if (!sslResult.value.valid) {
        scanResults.vulnerabilities.push({
          type: 'ssl_hostname_mismatch',
          severity: 'high',
          description: 'SSL Certificate with Wrong Hostname',
          details: `Certificate hostname does not match domain: ${domain}`,
          recommendation: 'Obtain a certificate that matches your domain name'
        });
      }

      if (!sslResult.value.valid) {
        scanResults.vulnerabilities.push({
          type: 'ssl_untrusted',
          severity: 'critical',
          description: 'SSL Certificate Cannot Be Trusted',
          details: `Certificate validation failed for ${domain}`,
          recommendation: 'Ensure certificate is issued by a trusted CA'
        });
      }

      if (sslResult.value.valid && sslResult.value.daysRemaining <= 30 && sslResult.value.daysRemaining > 0) {
        scanResults.vulnerabilities.push({
          type: 'ssl_expiring_soon',
          severity: 'medium',
          description: 'SSL Certificate Expiring Soon',
          details: `Certificate expires in ${sslResult.value.daysRemaining} days`,
          recommendation: 'Renew certificate before expiration'
        });
      }

      if (sslResult.value.daysRemaining < 0) {
        scanResults.vulnerabilities.push({
          type: 'ssl_expired',
          severity: 'critical',
          description: 'SSL Certificate Expired',
          details: `Certificate expired ${Math.abs(sslResult.value.daysRemaining)} days ago`,
          recommendation: 'Renew certificate immediately'
        });
      }

      // ✅ RUN CERT CHAIN AND TLS ANALYSIS IN PARALLEL
      const [certChainResult, tlsResult] = await Promise.allSettled([
        (async () => {
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
                if (currentCert.issuerCertificate && currentCert.issuerCertificate !== currentCert) {
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

            req.on('error', (e) => reject(e));
            req.setTimeout(5000, () => {
              req.destroy();
              reject(new Error('Timeout'));
            });
            req.end();
          });
        })(),
        analyzeTLSProtocols(domain)
      ]);

      if (certChainResult.status === 'fulfilled') {
        const certChain = certChainResult.value;
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
            details: `${expiringChainCerts.length} certificate(s) in the chain will expire within 30 days`,
            recommendation: 'Renew intermediate or root certificates in the chain'
          });
        }
      } else {
        scanResults.ssl.chainCheckError = certChainResult.reason?.message || 'Chain check failed';
      }

      if (tlsResult.status === 'fulfilled') {
        scanResults.ssl.tlsProtocols = tlsResult.value.protocols;
        scanResults.ssl.cipherSuites = tlsResult.value.cipherSuites;
        scanResults.ssl.alpnProtocols = tlsResult.value.alpnProtocols;
        scanResults.ssl.perfectForwardSecrecy = tlsResult.value.perfectForwardSecrecy;

        if (tlsResult.value.vulnerabilities?.length > 0) {
          scanResults.vulnerabilities.push(...tlsResult.value.vulnerabilities);
        }
      } else {
        scanResults.ssl.tlsCheckError = tlsResult.reason?.message || 'TLS check failed';
      }
    } else {
      scanResults.ssl = {
        valid: false,
        error: sslResult.reason?.message || 'SSL check failed',
        daysRemaining: null
      };

      scanResults.vulnerabilities.push({
        type: 'ssl_error',
        severity: 'high',
        description: 'SSL certificate issue detected',
        details: sslResult.reason?.message || 'Unknown error',
        recommendation: 'Verify SSL/TLS configuration'
      });
    }

    // Process Headers results
    let htmlBody = '';
    let finalUrlUsed = formattedUrl;

    if (headersResult.status === 'fulfilled') {
      const { response, timespan } = headersResult.value;
      scanResults.timespan = timespan;
      scanResults.headers = response.headers;

      const nodeRes = response?.request?.res;
      if (nodeRes && Array.isArray(nodeRes.rawHeaders) && nodeRes.rawHeaders.length) {
        scanResults.headers.rawHeaders = nodeRes.rawHeaders;
        scanResults.headers.httpVersion = nodeRes.httpVersion || '';
        scanResults.headers.statusCode = nodeRes.statusCode;
        scanResults.headers.statusMessage = nodeRes.statusMessage || '';
      } else {
        const flat = [];
        for (const [k, v] of Object.entries(response.headers)) {
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
        if (!response.headers[h]) {
          scanResults.vulnerabilities.push({
            type: 'header',
            severity: 'medium',
            description: message,
            details: `Missing header: ${h}`,
            recommendation: `Add the ${h} header`
          });
        }
      }

      if (response.headers.server) {
        scanResults.vulnerabilities.push({
          type: 'information_disclosure',
          severity: 'low',
          description: 'Server information disclosure',
          details: `Server header reveals: ${response.headers.server}`,
          recommendation: 'Avoid exposing server brand/version'
        });
      }

      const cookieFindings = parseSetCookie(response.headers['set-cookie']);
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

      const cspHeader = Array.isArray(response.headers['content-security-policy'])
        ? response.headers['content-security-policy'][0]
        : response.headers['content-security-policy'];
      const cspAnalysis = analyzeCSP(cspHeader);
      scanResults.headers.csp = cspAnalysis;

      if (!cspAnalysis.present || cspAnalysis.issues.length) {
        scanResults.vulnerabilities.push({
          type: 'csp',
          severity: cspAnalysis.present ? 'medium' : 'high',
          description: cspAnalysis.present ? 'CSP has issues' : 'CSP missing',
          details: cspAnalysis.issues.join('; '),
          recommendation: 'Harden CSP (add default-src, remove unsafe-* tokens, set frame-ancestors)'
        });
      }

      // Get HTML body
      try {
        const agentFollow = new https.Agent({ rejectUnauthorized: false });
        const htmlResp = await axios.get(formattedUrl, {
          timeout: 6000, // ✅ Reduced from 8000
          httpsAgent: agentFollow,
          validateStatus: () => true,
          maxRedirects: 5,
          responseType: 'text',
          transformResponse: [(d) => d]
        });
        htmlBody = typeof htmlResp.data === 'string' ? htmlResp.data : '';
        finalUrlUsed = htmlResp.request?.res?.responseUrl || formattedUrl;
      } catch { }

      const xfoMissing = !response.headers['x-frame-options'];
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
    } else {
      scanResults.vulnerabilities.push({
        type: 'connection',
        severity: 'medium',
        description: 'Failed to connect or retrieve headers',
        details: headersResult.reason?.message || 'Connection failed',
        recommendation: 'Ensure HTTPS is reachable and not blocking scanners'
      });
    }

    // Process Robots.txt
    if (robotsResult.status === 'fulfilled') {
      scanResults.robots = robotsResult.value;

      if (robotsResult.value.sitemaps?.length > 0) {
        scanResults.vulnerabilities.push({
          type: 'robots_sitemap',
          severity: 'info',
          description: 'Sitemaps Declared in robots.txt',
          details: `Found ${robotsResult.value.sitemaps.length} sitemap(s)`,
          recommendation: 'Ensure sitemaps are up-to-date'
        });
      }
    } else {
      scanResults.robots = { present: false, allowsAll: true, disallowRules: [], sitemaps: [] };
    }

    // ✅ PHASE 2: RUN HEAVY TASKS IN PARALLEL (20-30 seconds)
    console.log('[Scanner] Phase 2: Service Detection, Sitemap, 404, Web Mirror - Starting...');

    const [serviceResult, sitemapResult, check404Result, webMirrorResult] = await Promise.allSettled([
      // Service Detection
      detectServiceTechnology(domain, scanResults.headers || {}, htmlBody),

      // Sitemap Check
      (async () => {
        const agent = new https.Agent({ rejectUnauthorized: false });
        const sitemapUrls = [
          `https://${domain}/sitemap.xml`,
          `https://${domain}/sitemap_index.xml`,
          ...(scanResults.robots?.sitemaps || [])
        ];

        for (const sitemapUrl of sitemapUrls) {
          try {
            const resp = await axios.get(sitemapUrl, {
              timeout: 3000, // ✅ Reduced from 5000
              httpsAgent: agent,
              validateStatus: () => true,
            });

            if (resp.status === 200 && resp.data) {
              const summary = await summarizeSitemap(resp.data);
              return { url: sitemapUrl, ...summary };
            }
          } catch { }
        }
        return { present: false };
      })(),

      // 404 Check
      check404Handling(domain),

      // ✅ Web Mirroring (optimized settings)
      crawlWebsite(formattedUrl, {
        maxPages: 30,      // ✅ Reduced from 50
        maxDepth: 2,       // ✅ Reduced from 3
        timeout: 8000,     // ✅ Reduced from 15000
        onlySubdomain: true
      })
    ]);

    // Process Service Detection
    if (serviceResult.status === 'fulfilled') {
      scanResults.serviceDetection = serviceResult.value;

      // Add FQDN info
      try {
        const fqdnInfo = await resolveHostFQDN(domain);
        scanResults.serviceDetection.fqdnInfo = fqdnInfo;
      } catch { }

      // CGI vulnerabilities
      if (serviceResult.value.cgiTesting?.vulnerable) {
        scanResults.vulnerabilities.push({
          type: 'cgi_injectable',
          severity: 'high',
          description: 'CGI Generic Injectable Parameter',
          details: `Possible CGI injection vulnerability detected`,
          recommendation: 'Review and sanitize all CGI script inputs'
        });
      }

      if (serviceResult.value.cgiTesting?.tested) {
        scanResults.vulnerabilities.push({
          type: 'cgi_tested',
          severity: 'info',
          description: 'CGI Generic Tests Completed',
          details: `CGI endpoints tested. Vulnerable: ${serviceResult.value.cgiTesting.vulnerable ? 'Yes' : 'No'}`,
          recommendation: 'Regular CGI security testing recommended'
        });
      }

      // PostgreSQL detection
      if (serviceResult.value.postgresqlDetection?.detected) {
        scanResults.vulnerabilities.push({
          type: 'postgresql_detected',
          severity: 'info',
          description: 'PostgreSQL Server Detection',
          details: `PostgreSQL detected on port ${serviceResult.value.postgresqlDetection.port}`,
          recommendation: 'Ensure PostgreSQL is properly secured'
        });
      }

      // CPE information
      if (serviceResult.value.cpe?.length > 0) {
        scanResults.vulnerabilities.push({
          type: 'cpe_enumeration',
          severity: 'info',
          description: 'Common Platform Enumeration (CPE)',
          details: `Identified ${serviceResult.value.cpe.length} CPE entr(ies)`,
          recommendation: 'Monitor CVE databases for vulnerabilities'
        });
      }

      // Traceroute
      if (serviceResult.value.traceroute?.supported && serviceResult.value.traceroute.hops?.length > 0) {
        scanResults.vulnerabilities.push({
          type: 'traceroute_info',
          severity: 'info',
          description: 'Traceroute Information',
          details: `Network path traced: ${serviceResult.value.traceroute.totalHops} hops detected`,
          recommendation: 'Review network path for security and performance'
        });
      }

      // Network Timings
      if (serviceResult.value.networkTimings?.supported) {
        const timings = serviceResult.value.networkTimings.timings;
        scanResults.vulnerabilities.push({
          type: 'network_timings',
          severity: 'info',
          description: 'TCP/IP Network Timings',
          details: `DNS: ${timings.dnsLookup?.toFixed(2)}ms, TCP: ${timings.tcpConnection?.toFixed(2)}ms, TLS: ${timings.tlsHandshake?.toFixed(2)}ms, TTFB: ${timings.ttfb?.toFixed(2)}ms`,
          recommendation: 'Monitor network performance for optimization'
        });
      }

      // Application Servers
      if (serviceResult.value.applicationServers?.length > 0) {
        serviceResult.value.applicationServers.forEach(server => {
          scanResults.vulnerabilities.push({
            type: 'service_detection',
            severity: 'info',
            description: `${server.name} Detected`,
            details: `Application server detected via ${server.detected}`,
            recommendation: 'Ensure server is up-to-date'
          });
        });
      }

      // Tomcat
      const tomcatDetected = serviceResult.value.applicationServers?.find(
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

      // CMS
      if (serviceResult.value.cms) {
        scanResults.vulnerabilities.push({
          type: 'cms_detection',
          severity: 'info',
          description: `${serviceResult.value.cms.name} CMS Detected`,
          details: `Content Management System: ${serviceResult.value.cms.name}`,
          recommendation: `Keep ${serviceResult.value.cms.name} and plugins updated`
        });
      }
    } else {
      scanResults.serviceDetection = {
        error: serviceResult.reason?.message || 'Service detection failed'
      };
    }

    // Process Sitemap
    if (sitemapResult.status === 'fulfilled') {
      scanResults.sitemap = sitemapResult.value;

      if (sitemapResult.value.type) {
        scanResults.vulnerabilities.push({
          type: 'sitemap_found',
          severity: 'info',
          description: 'Web Application Sitemap',
          details: `Sitemap found: ${sitemapResult.value.type}`,
          recommendation: 'Ensure sitemap doesn\'t expose sensitive URLs'
        });
      }
    } else {
      scanResults.sitemap = { present: false };
    }

    // Process 404 Check
    if (check404Result.status === 'fulfilled') {
      scanResults.errorHandling.check404 = check404Result.value;

      if (!check404Result.value.properlyConfigured) {
        scanResults.vulnerabilities.push({
          type: '404_misconfigured',
          severity: 'low',
          description: 'Web Server No 404 Error Code Check',
          details: `Server returned status ${check404Result.value.statusCode} instead of 404`,
          recommendation: 'Configure server to return proper 404 status codes'
        });
      }
    }

    // ✅ Process Web Mirroring
    if (webMirrorResult.status === 'fulfilled') {
      scanResults.webMirror = webMirrorResult.value;
      console.log(`[Scanner] Web mirror complete: ${webMirrorResult.value.totalPages} pages found`);

      scanResults.vulnerabilities.push({
        type: 'web_mirror',
        severity: 'info',
        description: 'Web Application Structure Mapped',
        details: `Discovered ${webMirrorResult.value.totalPages} pages, ${webMirrorResult.value.totalDiscovered} unique URLs, ${webMirrorResult.value.assets?.totalAssets || 0} assets`,
        recommendation: 'Review exposed pages and ensure sensitive pages are properly protected'
      });

      // Check for sensitive paths
      const sensitivePaths = ['/admin', '/login', '/dashboard', '/api', '/config', '/backup', '/.git', '/.env'];
      const exposedSensitive = webMirrorResult.value.pages?.filter(page =>
        sensitivePaths.some(path => page.url.toLowerCase().includes(path))
      ) || [];

      if (exposedSensitive.length > 0) {
        scanResults.vulnerabilities.push({
          type: 'sensitive_paths_exposed',
          severity: 'medium',
          description: 'Potentially Sensitive Paths Discovered',
          details: `Found ${exposedSensitive.length} potentially sensitive URL(s)`,
          recommendation: 'Ensure sensitive paths are properly secured with authentication'
        });
      }
    } else {
      console.error('[Scanner] Web mirroring failed:', webMirrorResult.reason?.message);
      scanResults.webMirror = {
        error: webMirrorResult.reason?.message || 'Web mirroring failed',
        totalPages: 0,
        pages: []
      };
    }

    // HTML Form Analysis
    if (htmlBody) {
      try {
        const formAnalysis = analyzeHTMLForms(htmlBody, finalUrlUsed);
        scanResults.htmlAnalysis = formAnalysis;

        if (formAnalysis.autoCompleteIssues.length > 0) {
          scanResults.vulnerabilities.push({
            type: 'form_autocomplete',
            severity: 'medium',
            description: 'Web Server Allows Password Auto-Completion',
            details: `${formAnalysis.autoCompleteIssues.length} password field(s) allow autocomplete`,
            recommendation: 'Set autocomplete="off" or use "current-password"/"new-password" values'
          });
        }

        if (formAnalysis.cleartextCredentials) {
          scanResults.vulnerabilities.push({
            type: 'cleartext_credentials',
            severity: 'critical',
            description: 'Web Server Transmits Cleartext Credentials',
            details: 'Form with password field submits to HTTP (unencrypted) endpoint',
            recommendation: 'Use HTTPS for all forms transmitting sensitive data'
          });
        }

        if (formAnalysis.insecureActions.length > 0) {
          scanResults.vulnerabilities.push({
            type: 'insecure_form_action',
            severity: 'high',
            description: 'Forms Submit to Insecure HTTP Endpoints',
            details: `${formAnalysis.insecureActions.length} form(s) use HTTP actions`,
            recommendation: 'Change all form actions to use HTTPS'
          });
        }
      } catch (formError) {
        console.error('HTML form analysis error:', formError);
      }

      // Extract external URLs
      try {
        const externalUrls = extractExternalURLs(htmlBody, domain);
        if (scanResults.serviceDetection) {
          scanResults.serviceDetection.externalUrls = externalUrls;
        }
      } catch (urlError) {
        console.error('External URL extraction error:', urlError);
      }
    }

    // Vulnerability breakdown, risk, grade
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

    console.log('[Scanner] Scan complete, saving to database...');
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
