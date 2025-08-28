// controllers/reverseDnsController.js
import dns from "dns/promises";
import ReverseDNS from "../models/ReverseDNS.js";

// Optional libs (wrapped in try/catch so your server still runs if missing)
async function tryGeo(ip) {
  try {
    const mod = await import("geoip-lite");
    const geoip = mod.default || mod;
    return geoip.lookup(ip) || null; // { country, region, city, ll, timezone }
  } catch {
    return null;
  }
}
async function tryWhois(ip) {
  try {
    const mod = await import("whois-json");
    const whois = mod.default || mod;
    const w = await whois(ip, { follow: 1, timeout: 7000 });
    const asn =
      w.asn || w.ASN || w.originas || w.originAs || w.origin || w["origin"] || null;
    const org = w.org || w.OrgName || w["OrgName"] || w.netname || w.owner || w.Organization || null;
    const cidr = w.cidr || w.CIDR || null;
    const isp = w.isp || w.ISP || org || null;
    return { raw: w, asn, org, cidr, isp };
  } catch {
    return null;
  }
}

function isIPv4(ip) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(ip);
}

// ip → reverse name (in-addr.arpa / ip6.arpa)
function ipToReverseName(ip) {
  if (isIPv4(ip)) {
    return ip.split(".").reverse().join(".") + ".in-addr.arpa";
  }
  // IPv6 → expand then nibble-reverse
  const full = expandIPv6(ip);
  const nibbles = full.replace(/:/g, "").toLowerCase().split("");
  return nibbles.reverse().join(".") + ".ip6.arpa";
}
// naive but adequate IPv6 expander
function expandIPv6(ip) {
  if (ip.includes("::")) {
    const [head, tail] = ip.split("::");
    const headParts = head ? head.split(":") : [];
    const tailParts = tail ? tail.split(":") : [];
    const missing = 8 - (headParts.length + tailParts.length);
    const middle = new Array(missing).fill("0");
    const all = [...headParts, ...middle, ...tailParts].map((h) => h.padStart(4, "0"));
    return all.join(":");
  }
  return ip
    .split(":")
    .map((h) => h.padStart(4, "0"))
    .join(":");
}

async function getPtrTTL(reverseName) {
  try {
    // resolveAny returns records with 'type' and 'ttl'
    const rrset = await dns.resolveAny(reverseName);
    const ptr = rrset.find((r) => r.type === "PTR");
    if (ptr && typeof ptr.ttl === "number") return ptr.ttl;
  } catch {}
  return null;
}

async function forwardValidate(domains, ip) {
  const out = [];
  for (const domain of domains || []) {
    const [A, AAAA] = await Promise.all([
      dns.resolve4(domain).catch(() => []),
      dns.resolve6(domain).catch(() => []),
    ]);
    const matches =
      (isIPv4(ip) ? A.includes(ip) : false) ||
      (!isIPv4(ip) && AAAA.map((s) => s.toLowerCase()).includes(ip.toLowerCase()));
    out.push({ domain, resolved: { A, AAAA }, matches });
  }
  return out;
}

// DNSBLs to check (IPv4 only)
const DNSBLS = [
  "zen.spamhaus.org",
  "bl.spamcop.net",
  "b.barracudacentral.org",
  "dnsbl.sorbs.net",
  "cbl.abuseat.org",
];

async function dnsblQuery(ip) {
  if (!isIPv4(ip)) return { supported: false, listed: false, results: [] };
  const rev = ip.split(".").reverse().join(".");
  const results = await Promise.all(
    DNSBLS.map(async (zone) => {
      const q = `${rev}.${zone}`;
      try {
        const a = await dns.resolve4(q);
        return { zone, listed: true, addresses: a };
      } catch {
        return { zone, listed: false, addresses: [] };
      }
    })
  );
  return { supported: true, listed: results.some((r) => r.listed), results };
}

function humanTTL(sec) {
  if (sec == null) return null;
  let s = Number(sec);
  const d = Math.floor(s / 86400);
  s %= 86400;
  const h = Math.floor(s / 3600);
  s %= 3600;
  const m = Math.floor(s / 60);
  s = s % 60;
  return [d ? `${d}d` : null, h ? `${h}h` : null, m ? `${m}m` : null, s ? `${s}s` : null]
    .filter(Boolean)
    .join(" ") || "0s";
}

export const reverseDNSLookup = async (req, res) => {
  const { ip } = req.body || {};
  if (!ip) return res.status(400).json({ error: "IP address is required" });

  const t0 = Date.now();
  try {
    // 1) Reverse (PTR)
    const ptr = await dns.reverse(ip).catch(() => []);
    const reverseName = ipToReverseName(ip);
    const ttl = await getPtrTTL(reverseName);
    const ttlHuman = ttl != null ? humanTTL(ttl) : null;

    // 2) Extra intel in parallel
    const [geo, who, dnsbl, fwd] = await Promise.all([
      tryGeo(ip),
      tryWhois(ip),
      dnsblQuery(ip),
      forwardValidate(ptr, ip),
    ]);

    const ispName = who?.isp || who?.org || null;
    const asnText = who?.asn ? `AS${String(who.asn).replace(/^AS/i, "")}` : null;
    const displayName = ispName ? `${ispName}${asnText ? " (" + asnText + ")" : ""}` : null;

    const payload = {
      type: "PTR",
      ip,
      ptr,
      reverseName,
      ttl,
      ttlHuman,
      result: ptr.length ? "dns lookup found" : "no ptr record",
      test: "public",
      blacklist: dnsbl,
      geo: geo
        ? {
            country: geo.country,
            region: geo.region,
            city: geo.city,
            ll: geo.ll,
            timezone: geo.timezone,
          }
        : null,
      asn: who ? { asn: who.asn, org: who.org, isp: ispName, cidr: who.cidr } : null,
      displayName,
      forwardValidation: fwd,
      timespan: Date.now() - t0,
    };

    // 3) Save for history / analytics
    await ReverseDNS.findOneAndUpdate(
      { ip },
      {
        ...payload,
        domains: ptr,
        lookedUpAt: new Date(),
      },
      { upsert: true, new: true }
    );

    return res.json(payload);
  } catch (e) {
    console.error("Reverse DNS Lookup Failed:", e);
    return res.status(500).json({ error: "Lookup failed", details: e.message });
  }
};
