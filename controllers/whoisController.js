// controllers/whois.controller.js
import whois from 'whois';
import dns from 'dns/promises';
import { URL } from 'url';
import fetch from 'node-fetch';

// Optional APIs (set via env)
// VIRUSTOTAL_API_KEY
// GSB_API_KEY (Google Safe Browsing v4)
// WHOISXML_API_KEY (for reverse/historical whois)

const registrarCountries = {
  // expand as needed
  'Hostinger Operations, UAB': { country: 'Lithuania', cc: 'LT' },
  'Namecheap, Inc.': { country: 'United States', cc: 'US' },
  'GoDaddy.com, LLC': { country: 'United States', cc: 'US' },
  'Google LLC': { country: 'United States', cc: 'US' },
  'Tucows Domains Inc.': { country: 'Canada', cc: 'CA' },
};

const normalizeDomain = (input) => {
  const raw = String(input || '').trim();
  if (!raw) return null;
  try {
    const u = new URL(raw.includes('://') ? raw : `https://${raw}`);
    return u.hostname.toLowerCase();
  } catch {
    // allow bare domains that are valid-ish
    if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(raw)) return raw.toLowerCase();
    return null;
  }
};

const whoisLookup = (domain) =>
  new Promise((resolve, reject) => {
    whois.lookup(domain, (err, data) => {
      if (err) return reject(err);
      resolve(String(data || ''));
    });
  });

const pickLine = (raw, keys) => {
  const lines = raw.split('\n');
  for (const key of keys) {
    const rx = new RegExp(`^\\s*${key}\\s*:\\s*(.+)$`, 'i');
    const line = lines.find((ln) => rx.test(ln));
    if (line) return line.replace(rx, '$1').trim();
  }
  return null;
};

const pickAll = (raw, keys) => {
  const lines = raw.split('\n');
  const out = [];
  for (const ln of lines) {
    for (const key of keys) {
      const rx = new RegExp(`^\\s*${key}\\s*:\\s*(.+)$`, 'i');
      const m = ln.match(rx);
      if (m) out.push(m[1].trim());
    }
  }
  return Array.from(new Set(out));
};

const parseDate = (s) => {
  if (!s) return null;
  const tryParsers = [
    (v) => new Date(v),
    (v) => new Date(v.replace(/Z$/, '')),
  ];
  for (const p of tryParsers) {
    const d = p(s);
    if (!isNaN(d.getTime())) return d;
  }
  return null;
};

const calcAgeDays = (d) => {
  if (!d) return null;
  const ms = Date.now() - d.getTime();
  return Math.floor(ms / (1000 * 60 * 60 * 24));
};

const calcDaysUntil = (d) => {
  if (!d) return null;
  const ms = d.getTime() - Date.now();
  return Math.ceil(ms / (1000 * 60 * 60 * 24));
};

const deriveRegistrarGeo = (registrar) => {
  if (!registrar) return null;
  return registrarCountries[registrar] || null;
};

const detectPrivacy = (raw) => {
  const patterns = [
    /privacyprotect\.org/i,
    /whoisguard/i,
    /contact privacy/i,
    /privacy service/i,
    /redacted for privacy/i,
  ];
  return patterns.some((rx) => rx.test(raw));
};

const parseStatuses = (raw) =>
  pickAll(raw, ['Domain Status', 'Status']).map((s) =>
    s.replace(/\s*https?:\/\/\S+$/i, '').trim()
  );

const parseNameservers = (raw) =>
  pickAll(raw, ['Name Server', 'Nameserver']).map((ns) => ns.toLowerCase());

// Optional: VirusTotal domain report
const vtCheck = async (domain) => {
  const key = process.env.VIRUSTOTAL_API_KEY;
  if (!key) return { provider: 'VirusTotal', available: false };
  try {
    const resp = await fetch(`https://www.virustotal.com/api/v3/domains/${domain}`, {
      headers: { 'x-apikey': key },
    });
    if (!resp.ok) return { provider: 'VirusTotal', available: true, error: `HTTP ${resp.status}` };
    const data = await resp.json();
    const stats = data?.data?.attributes?.last_analysis_stats;
    const malicious = (stats?.malicious || 0) + (stats?.suspicious || 0);
    return {
      provider: 'VirusTotal',
      available: true,
      maliciousCount: malicious,
      clean: malicious === 0,
      raw: stats,
    };
  } catch (e) {
    return { provider: 'VirusTotal', available: true, error: String(e) };
  }
};

// Optional: Google Safe Browsing
const gsbCheck = async (domain) => {
  const key = process.env.GSB_API_KEY;
  if (!key) return { provider: 'Google Safe Browsing', available: false };
  try {
    const body = {
      client: { clientId: 'whois-tool', clientVersion: '1.0' },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url: `http://${domain}/` }, { url: `https://${domain}/` }],
      },
    };
    const resp = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${key}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!resp.ok) return { provider: 'Google Safe Browsing', available: true, error: `HTTP ${resp.status}` };
    const data = await resp.json();
    const matches = Array.isArray(data?.matches) ? data.matches : [];
    return {
      provider: 'Google Safe Browsing',
      available: true,
      clean: matches.length === 0,
      matches,
    };
  } catch (e) {
    return { provider: 'Google Safe Browsing', available: true, error: String(e) };
  }
};

// Optional: WhoisXML Reverse WHOIS + Historical
const whoisXmlReverse = async (emailOrOrg) => {
  const key = process.env.WHOISXML_API_KEY;
  if (!key || !emailOrOrg) return { available: false };
  try {
    const url = `https://reverse-whois.whoisxmlapi.com/api/v2?apiKey=${key}&mode=purchase-usage&terms=${encodeURIComponent(
      emailOrOrg
    )}`;
    const resp = await fetch(url);
    if (!resp.ok) return { available: true, error: `HTTP ${resp.status}` };
    const data = await resp.json();
    const domains = data?.result?.domainsList || [];
    return { available: true, domains };
  } catch (e) {
    return { available: true, error: String(e) };
  }
};

const whoisXmlHistory = async (domain) => {
  const key = process.env.WHOISXML_API_KEY;
  if (!key) return { available: false };
  try {
    const url = `https://whois-history.whoisxmlapi.com/api/v1?apiKey=${key}&domainName=${encodeURIComponent(domain)}&mode=purchase-usage`;
    const resp = await fetch(url);
    if (!resp.ok) return { available: true, error: `HTTP ${resp.status}` };
    const data = await resp.json();
    const history = data?.WhoisHistory || [];
    return { available: true, history };
  } catch (e) {
    return { available: true, error: String(e) };
  }
};

export const getWhoisData = async (req, res) => {
  try {
    const domain = normalizeDomain(req.body?.domain);
    if (!domain) return res.status(400).json({ error: 'Valid domain is required' });

    const raw = await whoisLookup(domain);

    // Parse fields
    const registrar = pickLine(raw, ['Registrar', 'Sponsoring Registrar']);
    const createdAtStr = pickLine(raw, ['Creation Date', 'Created On', 'Registered On']);
    const expiresAtStr = pickLine(raw, ['Registry Expiry Date', 'Expiration Date', 'Expiry Date', 'Registrar Registration Expiration Date']);
    const updatedAtStr = pickLine(raw, ['Updated Date', 'Last Updated On']);

    const createdAt = parseDate(createdAtStr);
    const expiresAt = parseDate(expiresAtStr);
    const updatedAt = parseDate(updatedAtStr);

    const domainAgeDays = createdAt ? calcAgeDays(createdAt) : null;
    const daysUntilExpiry = expiresAt ? calcDaysUntil(expiresAt) : null;

    const statuses = parseStatuses(raw);
    const nameservers = parseNameservers(raw);

    const dnssecField = pickLine(raw, ['DNSSEC']);
    const dnssec = dnssecField ? /signed/i.test(dnssecField) : false;

    // Basic contact detection (masked if privacy)
    const registrantEmail = pickLine(raw, ['Registrant Email']);
    const registrantOrg = pickLine(raw, ['Registrant Organization', 'Registrant Organisation']);
    const privacyProtected = detectPrivacy(raw);

    // Resolve IP + rDNS
    let ip = null, rDns = null, ipProvider = null;
    try {
      const a = await dns.lookup(domain); // chooses A/AAAA
      ip = a?.address || null;
      if (ip) {
        const ptr = await dns.reverse(ip).catch(() => []);
        rDns = Array.isArray(ptr) && ptr.length ? ptr[0] : null;
        // very light provider inference
        if (rDns) {
          if (/cloudflare/i.test(rDns)) ipProvider = 'Cloudflare';
          else if (/google|1e100/i.test(rDns)) ipProvider = 'Google';
          else if (/amazonaws|awsstatic/i.test(rDns)) ipProvider = 'Amazon AWS';
          else if (/hostinger/i.test(rDns)) ipProvider = 'Hostinger';
        }
      }
    } catch {}

    // Registrar geo
    const registrarGeo = deriveRegistrarGeo(registrar);

    // Threat intel (optional)
    const [vt, gsb] = await Promise.all([vtCheck(domain), gsbCheck(domain)]);

    // Reverse WHOIS & History (optional)
    const [reverseWhois, history] = await Promise.all([
      whoisXmlReverse(privacyProtected ? null : registrantEmail || registrantOrg),
      whoisXmlHistory(domain),
    ]);

    const summary = {
      domain,
      registrar,
      registrarGeo, // { country, cc } if mapped
      statuses,
      createdAt: createdAt?.toISOString() || null,
      updatedAt: updatedAt?.toISOString() || null,
      expiresAt: expiresAt?.toISOString() || null,
      domainAgeDays,
      daysUntilExpiry,
      privacyProtected,
      dnssecSigned: !!dnssec,
      nameservers,
      ip,
      rDns,
      ipProvider,
      threatIntel: {
        virusTotal: vt,
        googleSafeBrowsing: gsb,
      },
      reverseWhois,
      history,
    };

    return res.status(200).json({
      ok: true,
      summary,
      raw, // Full WHOIS text
    });
  } catch (err) {
    console.error('WHOIS error:', err);
    return res.status(500).json({ error: 'Failed to fetch WHOIS data' });
  }
};
