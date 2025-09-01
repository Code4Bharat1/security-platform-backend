// controllers/linkDetectorController.js
import fetch from "node-fetch"; // v2
import dns from "dns/promises";
import { domainToASCII } from "node:url";

import geoip from "geoip-lite";
import pLimit from "p-limit";
import LinkScan from "../models/LinkScan.js";

let puppeteer = null;
const ENABLE_SCREENSHOTS = process.env.LINKDETECTOR_SCREENSHOTS === "true";
if (ENABLE_SCREENSHOTS) {
  try {
    puppeteer = (await import("puppeteer")).default;
  } catch (e) {
    console.warn("Puppeteer not available; screenshots disabled.", e?.message);
  }
}

const MAX_REDIRECTS = Number(process.env.LINKDETECTOR_MAX_REDIRECTS || 5);
const REQUEST_TIMEOUT_MS = Number(process.env.LINKDETECTOR_TIMEOUT_MS || 7000);

// Extend/curate these lists for your environment:
const SHORTENERS = [
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "ow.ly",
  "shorturl.at",
  "rebrand.ly",
  "is.gd",
  "buff.ly",
  "cutt.ly",
  "grabify.link",
];

const SUSPICIOUS_KEYWORDS = [
  "login",
  "verify",
  "reset",
  "account",
  "token",
  "gift",
  "bonus",
  "prize",
  "bank",
  "wallet",
];

const MALICIOUS_PATTERNS = ["phishing", "malware", "trojan", "stealer"];

// Known brands for quick typosquat checks (minimal set; extend as needed)
const KNOWN_BRANDS = [
  "google.com",
  "facebook.com",
  "amazon.com",
  "apple.com",
  "microsoft.com",
  "instagram.com",
  "whatsapp.com",
  "netflix.com",
  "paypal.com",
];

const KNOWN_BAD_HOSTS = (process.env.LINKDETECTOR_BAD_HOSTS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// Helpers
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function normUrl(u) {
  try {
    const { protocol, hostname, pathname, search, hash } = new URL(u);
    const h = hostname.toLowerCase().replace(/\.$/, "");
    return `${protocol}//${h}${pathname}${search}${hash}`;
  } catch {
    return u;
  }
}

function eTLDPlusOne(hostname) {
  // naive eTLD+1 extractor (for full accuracy use 'tldts' lib)
  const parts = hostname.split(".").filter(Boolean);
  if (parts.length <= 2) return hostname;
  return parts.slice(-2).join(".");
}

function looksOnion(u) {
  try {
    const { hostname } = new URL(u);
    return /\.onion$/i.test(hostname);
  } catch {
    return false;
  }
}

function hasSuspiciousKeyword(u) {
  const lower = u.toLowerCase();
  return SUSPICIOUS_KEYWORDS.filter((k) => lower.includes(k));
}

function isShortener(host) {
  const h = host.toLowerCase();
  return SHORTENERS.some((s) => h === s || h.endsWith(`.${s}`));
}

function containsMaliciousPattern(u) {
  const lower = u.toLowerCase();
  return MALICIOUS_PATTERNS.some((p) => lower.includes(p));
}

function isHttps(u) {
  try {
    return new URL(u).protocol === "https:";
  } catch {
    return false;
  }
}

function asciiHostname(h) {
  const ascii = domainToASCII(h || "");
  return ascii || h; // domainToASCII returns "" if it can't convert
}

function simpleTyposquatCheck(host) {
  // basic: digits for letters (amaz0n, go0gle)
  const map = { "0": "o", "1": "l", "3": "e", "5": "s", "7": "t" };
  const deNoob = host.replace(/[01357]/g, (m) => map[m] || m);
  const hostETLD1 = eTLDPlusOne(host);
  for (const brand of KNOWN_BRANDS) {
    const b = brand.replace(/^www\./, "");
    if (hostETLD1 === b) continue;
    if (deNoob.includes(b.replace(/\./g, "")) || hostETLD1.includes(b)) {
      return b;
    }
  }
  return null;
}

async function followRedirects(startUrl) {
  let current = startUrl;
  const chain = [current];
  let usedShortener = false;

  for (let i = 0; i < MAX_REDIRECTS; i++) {
    let res;
    try {
      res = await fetch(current, {
        method: "HEAD",
        redirect: "manual",
        timeout: REQUEST_TIMEOUT_MS,
      });
    } catch {
      // Fallback to GET when HEAD fails
      try {
        res = await fetch(current, {
          method: "GET",
          redirect: "manual",
          timeout: REQUEST_TIMEOUT_MS,
        });
      } catch (e) {
        return { finalUrl: current, chain, ok: false, status: 0 };
      }
    }

    const status = res.status;
    if (status >= 300 && status < 400) {
      const loc = res.headers.get("location");
      if (!loc) return { finalUrl: current, chain, ok: false, status };
      const next = new URL(loc, current).toString();
      chain.push(next);
      if (isShortener(new URL(current).hostname)) usedShortener = true;
      current = next;
      continue;
    } else {
      return { finalUrl: current, chain, ok: res.ok, status };
    }
  }

  return { finalUrl: current, chain, ok: false, status: 310 }; // too many redirects
}

async function resolveIP(host) {
  try {
    const [a] = await dns.resolve(host, "A");
    return a;
  } catch {
    try {
      const [aaaa] = await dns.resolve(host, "AAAA");
      return aaaa;
    } catch {
      return null;
    }
  }
}

async function resolveCNAME(host) {
  try {
    const cnames = await dns.resolveCname(host);
    return cnames;
  } catch {
    return [];
  }
}

async function getHtml(u) {
  try {
    const res = await fetch(u, {
      method: "GET",
      redirect: "follow",
      timeout: REQUEST_TIMEOUT_MS,
      headers: { "User-Agent": "Mozilla/5.0 LinkDetector/1.0" },
    });
    if (!res.ok) return { ok: false, status: res.status, html: "" };
    const html = await res.text();
    return { ok: true, status: res.status, html };
  } catch {
    return { ok: false, status: 0, html: "" };
  }
}

function scanHtml(html) {
  const coinMiner = /(coinhive|webmine|cryptonight|miner)/i.test(html);
  const suspiciousEval = /(eval\(atob|Function\(|document\.write\(|onload=|setTimeout\(.+location)/i.test(
    html
  );
  const externalJsCount = (html.match(/<script[^>]+src=/gi) || []).length;
  const formsCount = (html.match(/<form/gi) || []).length;

  return {
    hasCryptoMiner: coinMiner,
    suspiciousInlineEval: suspiciousEval,
    externalJsCount,
    formsCount,
  };
}

function geoLookup(ip) {
  if (!ip) return {};
  const g = geoip.lookup(ip);
  if (!g) return {};
  return {
    ip,
    country: g.country,
    region: g.region,
    city: g.city,
    ll: g.ll,
  };
}

function computeTrustIndex({
  sslHttps,
  onion,
  redirectLen,
  suspiciousKwCount,
  typosquatOf,
  contentFindings,
  blacklistMatches,
  shortenerExpanded,
  domainBad,
}) {
  // Start neutral, then subtract risk factors; clamp 0..100
  let score = 80;

  if (!sslHttps) score -= 10;
  if (onion) score -= 40;

  if (redirectLen >= 3) score -= 10;
  if (redirectLen >= 5) score -= 15;

  score -= Math.min(20, suspiciousKwCount * 5);
  if (typosquatOf) score -= 20;

  if (contentFindings?.hasCryptoMiner) score -= 25;
  if (contentFindings?.suspiciousInlineEval) score -= 15;
  if ((contentFindings?.externalJsCount || 0) > 20) score -= 10;

  if (blacklistMatches?.length) score -= 30;

  if (shortenerExpanded) score -= 5;
  if (domainBad) score -= 30;

  if (score > 100) score = 100;
  if (score < 0) score = 0;
  return score;
}

function statusFromScore(score) {
  if (score >= 70) return "safe";
  if (score >= 40) return "suspicious";
  return "malicious";
}

function domainIsBad(host) {
  return KNOWN_BAD_HOSTS.includes(host) || KNOWN_BAD_HOSTS.includes(eTLDPlusOne(host));
}

async function captureScreenshot(url) {
  if (!puppeteer) return null;
  const browser = await puppeteer.launch({
    headless: "new",
    args: ["--no-sandbox", "--disable-setuid-sandbox"],
  });
  try {
    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 800 });
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: REQUEST_TIMEOUT_MS });
    await sleep(500); // small settle
    const ts = Date.now();
    const file = `screenshots/linkdetector_${ts}.png`;
    await page.screenshot({ path: file, fullPage: false });
    return file;
  } catch {
    return null;
  } finally {
    await browser.close();
  }
}

// ---- Core analyzer ----
export async function analyzeUrl(url) {
  const evidence = [];
  let normalizedUrl = normUrl(url);
  let onion = looksOnion(normalizedUrl);

  // punycode normalize
  try {
    const u = new URL(normalizedUrl);
    u.hostname = asciiHostname(u.hostname);
    normalizedUrl = u.toString();
  } catch {}

  // Redirects / expansion
  const redir = await followRedirects(normalizedUrl);
  const finalUrl = redir.finalUrl;
  const redirectChain = redir.chain;
  evidence.push({ name: "redirectChain", value: redirectChain });

  // Basic checks
  const sslHttps = isHttps(finalUrl);
  const suspiciousKeywords = hasSuspiciousKeyword(finalUrl);
  const host = (() => {
    try {
      return new URL(finalUrl).hostname.toLowerCase();
    } catch {
      return "";
    }
  })();

  const shortenerExpanded = isShortener(host);
  const typosquatOf = simpleTyposquatCheck(host) || "No typosquatting detected"; // Fixed to prevent blank
  const maliciousPattern = containsMaliciousPattern(finalUrl);
  const domainBad = domainIsBad(host);

  if (maliciousPattern) evidence.push({ name: "maliciousPattern", value: true });
  if (typosquatOf !== "No typosquatting detected") evidence.push({ name: "typosquatOf", value: typosquatOf });
  if (shortenerExpanded) evidence.push({ name: "shortenerExpanded", value: true });

  // DNS / IP / Geo
  const cnames = await resolveCNAME(host);
  const ip = await resolveIP(host);
  const geo = geoLookup(ip);

  // Blacklist (local-only; integrate external feeds if needed)
  const blacklistMatches = domainBad ? ["local-bad-hosts"] : [];

  // Content scan (GET final HTML)
  let contentFindings = {};
  if (!onion && redir.ok) {
    const { ok, html } = await getHtml(finalUrl);
    if (ok) {
      contentFindings = scanHtml(html);
      evidence.push({ name: "contentFindings", value: contentFindings });
    }
  }

  // Screenshot (optional)
  let screenshotPath = null;
  if (ENABLE_SCREENSHOTS && !onion && redir.ok) {
    screenshotPath = await captureScreenshot(finalUrl);
  }

  // Compute score + status
  const trustIndex = computeTrustIndex({
    sslHttps,
    onion,
    redirectLen: redirectChain.length - 1,
    suspiciousKwCount: suspiciousKeywords.length,
    typosquatOf,
    contentFindings,
    blacklistMatches,
    shortenerExpanded,
    domainBad,
  });

  const status = maliciousPattern
    ? "malicious"
    : redir.ok
    ? statusFromScore(trustIndex)
    : "invalid";

  const message =
    status === "invalid"
      ? `Link not reachable (status ${redir.status}).`
      : status === "safe"
      ? "Link looks OK based on current heuristics."
      : status === "suspicious"
      ? "Potential risks detected. Review details."
      : "High risk indicators detected.";

  return {
    url,
    normalizedUrl,
    finalUrl,
    redirectChain,
    status,
    message,
    ssl: { isHttps: sslHttps },
    onion,
    suspicious: {
      keywordsFound: suspiciousKeywords,
      typosquatOf,
      shortenerExpanded,
      suspiciousDomain: domainBad,
      cnameChain: cnames,
      blacklistMatches,
    },
    contentFindings,
    geo,
    trustIndex,
    evidence,
    screenshotPath,
  };
}


// ---- Express handlers ----
export const scanLink = async (req, res) => {
  try {
    const { url } = req.body;
    if (!url || typeof url !== "string") {
      return res.status(400).json({ message: "Provide 'url' string." });
    }

    const analyzed = await analyzeUrl(url);

    const saved = await LinkScan.create({
      ...analyzed,
      scannedAt: new Date(),
    });

    res.json({
      ...analyzed,
      scannedAt: saved.scannedAt,
    });
  } catch (err) {
    console.error("scanLink error:", err);
    res.status(500).json({ message: "Server error during link scan." });
  }
};

export const bulkScan = async (req, res) => {
  try {
    const { urls } = req.body;
    if (!Array.isArray(urls) || urls.length === 0) {
      return res.status(400).json({ message: "Provide 'urls': string[] ." });
    }
    const limit = pLimit(Number(process.env.LINKDETECTOR_CONCURRENCY || 4));
    const tasks = urls.map((u) =>
      limit(async () => {
        try {
          const analyzed = await analyzeUrl(u);
          await LinkScan.create({ ...analyzed, scannedAt: new Date() });
          return { ok: true, ...analyzed };
        } catch (e) {
          return { ok: false, url: u, error: e?.message || "failed" };
        }
      })
    );

    const results = await Promise.all(tasks);
    res.json({ count: results.length, results });
  } catch (err) {
    console.error("bulkScan error:", err);
    res.status(500).json({ message: "Server error during bulk scan." });
  }
};

export const history = async (req, res) => {
  try {
    const { url } = req.query;
    if (!url) return res.status(400).json({ message: "Provide 'url' query." });
    const normalizedUrl = normUrl(url);
    const items = await LinkScan.find({ normalizedUrl })
      .sort({ scannedAt: -1 })
      .limit(100)
      .lean();
    res.json({ url, normalizedUrl, items });
  } catch (err) {
    console.error("history error:", err);
    res.status(500).json({ message: "Server error." });
  }
};
