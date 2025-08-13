// controllers/dnsController.js
import fetch from 'node-fetch';
import tls from 'tls';
import DNSLog from '../models/dnsModel.js';

// ------------- Helpers -------------
const dnsDoH = async (name, type = 'A') => {
  const url = `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
  const res = await fetch(url, { timeout: 10000 });
  if (!res.ok) throw new Error(`DoH failed (${res.status})`);
  return res.json();
};

const rdapLookup = async (domain) => {
  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, { timeout: 12000 });
    if (!res.ok) throw new Error(`RDAP ${res.status}`);
    const json = await res.json();

    // Parse registrar (RDAP varies a lot)
    let registrar = '';
    if (Array.isArray(json.entities)) {
      const reg = json.entities.find(e => Array.isArray(e.roles) && e.roles.includes('registrar'));
      if (reg?.vcardArray?.[1]) {
        const fn = reg.vcardArray[1].find(v => v[0] === 'fn');
        registrar = fn?.[3] || '';
      }
      registrar ||= reg?.handle || reg?.objectClassName || '';
    }
    // Dates from events
    const events = Array.isArray(json.events) ? json.events : [];
    const created = events.find(e => e.eventAction === 'registration')?.eventDate || '';
    const expires = events.find(e => e.eventAction === 'expiration')?.eventDate || '';

    return { registrar, created, expires, raw: json };
  } catch (e) {
    return { registrar: '', created: '', expires: '', error: e.message };
  }
};

const getSslInfo = (domain) =>
  new Promise((resolve) => {
    const socket = tls.connect({
      host: domain,
      port: 443,
      servername: domain,
      rejectUnauthorized: false, // we only read cert info
      timeout: 12000,
    }, () => {
      try {
        const proto = socket.getProtocol?.() || '';
        const cert = socket.getPeerCertificate(true);
        const issuer = cert?.issuer?.O || cert?.issuer?.CN || cert?.issuerCertificate?.subject?.O || '';
        const validFrom = cert?.valid_from || '';
        const validTo = cert?.valid_to || '';
        resolve({
          issuer,
          protocol: proto,      // e.g., 'TLSv1.3'
          validFrom,
          validTo,
          subjectCN: cert?.subject?.CN || ''
        });
      } catch (e) {
        resolve({ issuer: '', protocol: '', validFrom: '', validTo: '', error: e.message });
      } finally {
        socket.end();
      }
    });
    socket.on('error', (err) => resolve({ issuer: '', protocol: '', validFrom: '', validTo: '', error: err.message }));
    socket.on('timeout', () => { socket.destroy(); resolve({ issuer: '', protocol: '', validFrom: '', validTo: '', error: 'TLS timeout' }); });
  });

const fetchWithFallbacks = async (domain) => {
  // Try HTTPS, then HTTP (some small sites)
  const urls = [`https://${domain}`, `http://${domain}`];
  for (const url of urls) {
    try {
      const res = await fetch(url, {
        redirect: 'follow',
        headers: { 'User-Agent': 'Mozilla/5.0 ReconBot' },
        timeout: 12000
      });
      const text = await res.text();
      return { urlUsed: url, headers: Object.fromEntries(res.headers.entries()), html: text };
    } catch (_) {}
  }
  return { urlUsed: '', headers: {}, html: '' };
};

const detectTechnologies = async (domain) => {
  const { urlUsed, headers, html } = await fetchWithFallbacks(domain);

  const tech = { frontend: [], backend: [], headers };

  // Frontend heuristics
  if (/bootstrap(\.min)?\.css|Bootstrap v/i.test(html)) tech.frontend.push('Bootstrap');
  const jqMatch = html.match(/jquery(?:[-.](\d+\.\d+(?:\.\d+)?))?\.js/i);
  if (jqMatch) tech.frontend.push(`jQuery${jqMatch[1] ? ' ' + jqMatch[1] : ''}`);

  // Backend heuristics from headers
  const server = headers['server'];
  if (server?.toLowerCase().includes('apache')) tech.backend.push('Apache');
  const xpb = headers['x-powered-by'];
  if (xpb) {
    if (/php/i.test(xpb)) {
      const v = xpb.match(/php\/?([\d.]+)/i)?.[1];
      tech.backend.push(`PHP${v ? ' ' + v : ''}`);
    }
    // You can add more here (Express, ASP.NET, etc.)
  }

  // Meta generator as hint (WordPress, etc.) – optional
  const gen = html.match(/<meta[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']/i)?.[1];
  if (gen) tech.backend.push(`Generator: ${gen}`);

  return { urlUsed, tech };
};

const geoIpLookup = async (ip) => {
  try {
    const r = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, { timeout: 10000 });
    const j = await r.json();
    return {
      ip,
      success: j.success !== false,
      country: j.country || '',
      region: j.region || '',
      city: j.city || '',
      isp: j.connection?.isp || j.isp || '',
      latitude: j.latitude,
      longitude: j.longitude,
      raw: j
    };
  } catch (e) {
    return { ip, success: false, error: e.message };
  }
};

// ------------- Existing minimal DNS resolve (kept) -------------
export const resolveDNS = async (req, res) => {
  const { domain, type = 'A' } = req.body;
  if (!domain) {
    return res.status(400).json({ success: false, error: 'Domain is required' });
  }
  try {
    const data = await dnsDoH(domain, type);

    // Optional: Save the lookup to MongoDB (matches your existing behavior)
    try { await DNSLog.create({ domain, type, result: data }); } catch {}

    return res.status(200).json({ success: true, data });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
};

// ------------- NEW: Full Recon Scan -------------
export const reconScan = async (req, res) => {
  const { domain } = req.body || {};
  if (!domain) return res.status(400).json({ success: false, error: 'Domain is required' });

  // normalize
  const target = String(domain).trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '');

  try {
    // DNS (A, AAAA, MX, TXT, NS)
    const [dnsA, dnsAAAA, dnsMX, dnsTXT, dnsNS] = await Promise.allSettled([
      dnsDoH(target, 'A'), dnsDoH(target, 'AAAA'), dnsDoH(target, 'MX'), dnsDoH(target, 'TXT'), dnsDoH(target, 'NS')
    ]);

    const dns = {
      A: dnsA.value || null,
      AAAA: dnsAAAA.value || null,
      MX: dnsMX.value || null,
      TXT: dnsTXT.value || null,
      NS: dnsNS.value || null
    };

    // Choose an IPv4 for Geo-IP if available
    const ip =
      (dnsA.value?.Answer?.find(a => a.type === 1)?.data) ||
      (dnsA.value?.Answer?.[0]?.data) ||
      '';

    // WHOIS (RDAP)
    const whois = await rdapLookup(target);

    // SSL/TLS
    const ssl = await getSslInfo(target);

    // Tech detection
    const { urlUsed, tech } = await detectTechnologies(target);

    // Geo-IP
    const geoip = ip ? await geoIpLookup(ip) : { ip: '', success: false, error: 'No IPv4 A record' };

    // Optional: store a log document if your schema allows
    try { await DNSLog.create({ domain: target, type: 'RECON', result: { dns, whois, ssl, tech, geoip, urlUsed } }); } catch {}

    return res.status(200).json({
      success: true,
      domain: target,
      urlUsed,
      dns,
      whois: {
        registrar: whois.registrar || '',
        created: whois.created || '',
        expires: whois.expires || ''
      },
      ssl: {
        issuer: ssl.issuer || '',
        protocol: ssl.protocol || '',
        validFrom: ssl.validFrom || '',
        validTo: ssl.validTo || ''
      },
      technologies: tech,
      geoip
    });
  } catch (e) {
    return res.status(500).json({ success: false, error: e.message });
  }
};
