// controllers/openRedirect.controller.js
import axios from 'axios';
import { URL } from 'url';
import { OpenRedirect } from '../models/openRedirectModel.js';

/* --------------------- Helpers --------------------- */

// Very simple eTLD+1 heuristic (ok for common TLDs; replace with PSL lib if needed)
function etldPlusOne(hostname = '') {
  const parts = (hostname || '').toLowerCase().split('.').filter(Boolean);
  if (parts.length <= 2) return parts.join('.');
  // naive: last two labels
  return parts.slice(-2).join('.');
}

function sameSite(a, b) {
  return etldPlusOne(a) === etldPlusOne(b);
}

function isSubdomain(sub, root) {
  if (!sub || !root) return false;
  const s = sub.toLowerCase();
  const r = root.toLowerCase();
  return s !== r && s.endsWith(`.${r}`);
}

// Build tested URL by setting/adding paramName to desired value
function withParam(urlStr, paramName, value) {
  const u = new URL(urlStr);
  u.searchParams.set(paramName, value);
  return u.toString();
}

// Manual redirect following to capture chain
async function followChain(startUrl, { timeout = 10000, maxHops = 10, headers = {} } = {}) {
  const chain = [];
  let current = startUrl;
  let finalUrl = startUrl;
  for (let i = 0; i < maxHops; i++) {
    try {
      const resp = await axios.get(current, {
        maxRedirects: 0, // don't auto-follow
        timeout,
        validateStatus: () => true,
        headers,
      });

      const status = resp.status;
      const location = resp.headers?.location;

      // push hop (even if 200 OK)
      chain.push({
        status,
        location: location || '',
        url: current,
      });

      // if not a redirect code, we are done
      if (![300, 301, 302, 303, 307, 308].includes(status) || !location) {
        finalUrl = current;
        break;
      }

      // resolve location against current
      const nextUrl = new URL(location, current).toString();
      current = nextUrl;
      finalUrl = nextUrl;

    } catch (e) {
      chain.push({ status: 'ERR', location: '', url: current, error: e.message });
      break;
    }
  }
  return { chain, finalUrl };
}

// Payload variants to try (name -> generator)
const PAYLOADS = [
  ['baseline',    (host) => `https://${host}`],
  ['schemeLess',  (host) => `//${host}`],
  ['plainHost',   (host) => host],                           // some apps prepend scheme
  ['atHost',      (host) => `https://victim.com@${host}`],   // userinfo trick
  ['pathBreak',   (host) => `/\\/${host}`],                  // /\/evil.com
  ['encoded',     (host) => encodeURIComponent(`https://${host}`)],
  ['doubleEnc',   (host) => encodeURIComponent(encodeURIComponent(`https://${host}`))],
  ['dotEscape',   (host) => `https://${host}%2F..`],
];

const COMMON_PARAMS = ['redirect','url','next','dest','destination','continue','return','to','goto','r','u'];

/* --------------------- Controller --------------------- */

export const testOpenRedirectAdvanced = async (req, res) => {
  const { url, mode = 'auto', paramName, params } = req.body || {};

  if (!url) return res.status(400).json({ error: 'URL is required.' });

  let testedParams = [];
  try {
    const u = new URL(url);
    const present = Array.from(u.searchParams.keys());
    if (mode === 'manual' && paramName) {
      testedParams = [paramName];
    } else {
      // auto mode: use provided list or defaults; prefer ones already present in URL first
      const scanList = Array.isArray(params) && params.length ? params : COMMON_PARAMS;
      const inUrl = scanList.filter(p => present.includes(p));
      const notInUrl = scanList.filter(p => !present.includes(p));
      testedParams = [...new Set([...inUrl, ...notInUrl])];
    }
  } catch {
    return res.status(400).json({ error: 'Invalid URL.' });
  }

  const originalDomain = new URL(url).hostname;
  const originalETLD = etldPlusOne(originalDomain);
  const evilHost = 'evil.com'; // can make this configurable

  const tests = [];
  let anyVuln = false;
  let anyWhitelistBypass = false;
  let reasons = [];

  for (const p of testedParams) {
    // First try baseline to detect blocking behavior
    const baselinePayload = PAYLOADS.find(([n]) => n === 'baseline');
    const baselineUrl = withParam(url, p, baselinePayload[1](evilHost));
    const baseHop = await followChain(baselineUrl);

    const baseFinalHost = (() => {
      try { return new URL(baseHop.finalUrl).hostname; } catch { return ''; }
    })();

    const baseChangedETLD = baseFinalHost && !sameSite(baseFinalHost, originalDomain);
    const baselineVuln = Boolean(baseFinalHost && baseChangedETLD);
    const baselineRecord = {
      param: p,
      payloadName: 'baseline',
      testedUrl: baselineUrl,
      chain: baseHop.chain,
      finalUrl: baseHop.finalUrl,
      finalDomain: baseFinalHost,
      changedETLD: baseChangedETLD,
      vulnerable: baselineVuln,
      whitelistBypass: false,
    };
    tests.push(baselineRecord);
    if (baselineVuln) {
      anyVuln = true;
      reasons.push(`[${p}] baseline payload caused cross-site redirect to ${baseFinalHost}`);
    }

    // Try additional payloads
    for (const [name, gen] of PAYLOADS) {
      if (name === 'baseline') continue;
      const testUrl = withParam(url, p, gen(evilHost));
      const hop = await followChain(testUrl);
      const finalHost = (() => {
        try { return new URL(hop.finalUrl).hostname; } catch { return ''; }
      })();

      const changedETLD = finalHost && !sameSite(finalHost, originalDomain);
      const vulnerable = Boolean(finalHost && changedETLD);

      // Whitelist bypass heuristic: baseline not vulnerable but variant is
      const whitelistBypass = !baselineVuln && vulnerable;

      tests.push({
        param: p,
        payloadName: name,
        testedUrl: testUrl,
        chain: hop.chain,
        finalUrl: hop.finalUrl,
        finalDomain: finalHost,
        changedETLD,
        vulnerable,
        whitelistBypass,
      });

      if (vulnerable) {
        anyVuln = true;
        reasons.push(`[${p}] ${name} payload redirected to ${finalHost} (cross-site)`);
      }
      if (whitelistBypass) {
        anyWhitelistBypass = true;
        reasons.push(`[${p}] whitelist bypass via ${name} payload (baseline blocked, variant escaped).`);
      }
    }
  }

  // Compute severity
  // Critical: whitelist bypass to cross-site or multiple params leak to cross-site
  // High: any cross-site redirect without bypass
  // Medium: only subdomain redirects
  // Low: same-site redirects with weak validation indicators (e.g., scheme-less accepted but still resolves same eTLD)
  // Informational: no redirect or strictly stays on original with strong codes
  let severity = 'Informational';

  const crossSiteTests = tests.filter(t => t.vulnerable && t.changedETLD);
  const subdomainOnly = tests.filter(t => !t.changedETLD && t.finalDomain && isSubdomain(t.finalDomain, originalDomain));

  if (anyWhitelistBypass) {
    severity = 'Critical';
  } else if (crossSiteTests.length > 0) {
    severity = crossSiteTests.length > 1 ? 'High' : 'High';
  } else if (subdomainOnly.length > 0) {
    severity = 'Medium';
  } else {
    // Optional: detect weak signs
    const weak = tests.some(t =>
      t.chain.some(h => typeof h.status === 'number' && [301,302,303,307,308].includes(h.status))
    );
    severity = weak ? 'Low' : 'Informational';
  }

  if (!anyVuln && reasons.length === 0) {
    reasons.push('No payload caused a cross-site redirect.');
  }

  const payload = {
    originalUrl: url,
    originalDomain,
    summary: {
      vulnerable: anyVuln,
      whitelistBypass: anyWhitelistBypass,
      severity,
      reasons: Array.from(new Set(reasons)).slice(0, 12),
    },
    tests,
  };

  // Best-effort persistence without breaking if schema is strict
  try {
    if (OpenRedirect?.create) {
      await OpenRedirect.create({
        originalUrl: url,
        originalDomain,
        vulnerable: anyVuln,
        severity,
        testedAt: new Date(),
        // If your schema allows, store details:
        details: payload, // remove if schema is strict
      });
    }
  } catch (e) {
    // Non-fatal: log and continue
    console.warn('OpenRedirect save warning:', e.message);
  }

  return res.json(payload);
};
  