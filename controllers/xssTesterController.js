// controllers/xssTesterController.js
import axios from 'axios';
import * as cheerio from 'cheerio';
import { chromium } from 'playwright';
import { XssTest } from '../models/xssTestModel.js';

/** ---------- helpers ---------- */

// lightweight context detection from a reflected HTML snippet
function detectContext(snippet) {
  if (!snippet) return null;
  // inside <script> ... payload ...
  if (/<script[^>]*>[^<]*?__PAYLOAD__[^<]*<\/script>/i.test(snippet)) return 'javascript';
  // attribute context: <img src="__PAYLOAD__"> or attr="...__PAYLOAD__..."
  if (/<[a-z0-9\-]+[^>]*?=["'][^"']*__PAYLOAD__[^"']*["']/i.test(snippet)) return 'attribute';
  // URL-ish: href/src/javascript:
  if (/href=["'](?:javascript:)?__PAYLOAD__/i.test(snippet) || /src=["']__PAYLOAD__/i.test(snippet)) return 'url';
  // generic body/text
  if (/__PAYLOAD__/.test(snippet)) return 'html';
  return null;
}

// mark reflected payload region
function highlightReflection(html, payload) {
  if (!html || !payload) return null;
  const safePayload = payload.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const rx = new RegExp(safePayload, 'i');
  if (!rx.test(html)) return null;
  return html.replace(rx, '[[[PAYLOAD_HIT::' + payload + ']]]'); // easy visual marker
}

// quick WAF detection
function detectWaf(resp) {
  const headers = Object.fromEntries(Object.entries(resp?.headers || {}).map(([k, v]) => [k.toLowerCase(), String(v)]));
  const body = typeof resp?.data === 'string' ? resp.data.slice(0, 5000) : '';
  const server = headers['server'] || '';
  const cf = headers['cf-ray'] || headers['cf-cache-status'] || server.includes('cloudflare');
  const sucuri = /sucuri/i.test(server) || /sucuri/i.test(body);
  const akamai = /akamai/i.test(server) || /akamai/i.test(body);
  const imperva = /imperva|incapsula/i.test(server) || /incapsula/i.test(body);

  const vendor = cf ? 'Cloudflare' : sucuri ? 'Sucuri' : akamai ? 'Akamai' : imperva ? 'Imperva' : null;
  const detected = !!vendor || [403, 406].includes(resp?.status);
  return { detected, vendor };
}

// simple rate-limit detection
function detectRateLimit(resp) {
  const headers = Object.fromEntries(Object.entries(resp?.headers || {}).map(([k, v]) => [k.toLowerCase(), String(v)]));
  const status = resp?.status;
  const rl = status === 429 || headers['retry-after'];
  return rl ? { detected: true, reason: headers['retry-after'] ? `Retry-After=${headers['retry-after']}` : 'HTTP 429' } : { detected: false };
}

// CWE mapping + risk scoring
function scoreRisk({ reflected, domExecuted, context }) {
  // very simplified:
  if (domExecuted) return { risk: 'High', cwe: 'CWE-79 (DOM)', score: 9.0 };
  if (reflected && (context === 'javascript' || context === 'attribute')) return { risk: 'Medium', cwe: 'CWE-79', score: 6.5 };
  if (reflected) return { risk: 'Low', cwe: 'CWE-79', score: 3.1 };
  return { risk: 'None', cwe: null, score: 0 };
}

// try auto-bypass variants for payloads
function expandBypasses(p) {
  const variants = new Set([p]);
  const enc = encodeURIComponent(p);
  variants.add(enc);
  variants.add(p.replace(/script/gi, s => s[0] + s.slice(1).toUpperCase())); // ScRiPt-ish
  variants.add(p.replace(/</g, '&lt;').replace(/>/g, '&gt;'));
  variants.add(p.replace(/alert/gi, 'confirm'));
  return Array.from(variants);
}

async function httpGet(testUrl) {
  try {
    const resp = await axios.get(testUrl, {
      timeout: 10000,
      validateStatus: () => true,
      headers: {
        'User-Agent': 'SecPlatform-XSS-Scanner/1.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      },
    });
    return resp;
  } catch (e) {
    return { error: e.message };
  }
}

async function domScan(url) {
  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext();
  const page = await ctx.newPage();

  let domExecuted = false;
  // intercept alert/confirm/prompt to flag execution
  await page.addInitScript(() => {
    ['alert', 'confirm', 'prompt'].forEach(fn => {
      const orig = window[fn];
      window[fn] = (...args) => {
        window.__XSS_HIT__ = true;
        try { return orig?.apply(window, args); } catch { /* no-op */ }
      };
    });
  });

  try {
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 15000 });
    await page.waitForTimeout(1200);
    domExecuted = await page.evaluate(() => !!window.__XSS_HIT__);

    // screenshot if executed (or always if you prefer)
    const buf = await page.screenshot({ fullPage: true });
    await browser.close();
    return { domExecuted, screenshotBase64: buf.toString('base64') };
  } catch (e) {
    await browser.close();
    return { domExecuted: false, error: e.message };
  }
}

/** ---------- main controller ---------- */

export const testXssPayload = async (req, res) => {
  const { url, param, payload, payloads, domScan: runDomScan, takeScreenshots, autoBypass } = req.body;

  if (!url || !param || (!payload && !payloads?.length)) {
    return res.status(400).json({ error: 'url, param, and at least one payload are required' });
  }

  // normalize list
  let toTest = payloads?.length ? payloads : [payload];

  // expand bypasses if requested
  if (autoBypass) {
    toTest = Array.from(new Set(toTest.flatMap(p => expandBypasses(p))));
  }

  const runs = [];
  let wafAgg = { detected: false, vendor: null };
  let rateAgg = { detected: false, reason: null };
  let executedCount = 0, low=0, med=0, high=0;

  for (const p of toTest) {
    const testUrl = new URL(url);
    testUrl.searchParams.set(param, p);

    const httpResp = await httpGet(testUrl.toString());
    let status = httpResp?.status || (httpResp?.error ? 'ERR' : '—');
    const bodyStr = typeof httpResp?.data === 'string' ? httpResp.data : (httpResp?.data ? JSON.stringify(httpResp.data) : '');

    // reflection & highlight
    const reflected = bodyStr?.includes(p);
    let highlighted = null, context = null;

    if (reflected) {
      // create a short snippet to detect context
      const around = 600;
      const idx = bodyStr.indexOf(p);
      const slice = bodyStr.slice(Math.max(0, idx - around), idx + p.length + around);
      const marked = slice.replace(new RegExp(p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')), '__PAYLOAD__');
      context = detectContext(marked);
      highlighted = highlightReflection(slice, p);
    }

    // WAF / Rate limits
    const waf = detectWaf(httpResp);
    const rateLimit = detectRateLimit(httpResp);
    if (waf.detected) { wafAgg = waf; }
    if (rateLimit.detected) { rateAgg = rateLimit; }

    // Optional DOM scan (headless)
    let domExecuted = false;
    let screenshots = [];
    if (runDomScan) {
      const domRes = await domScan(testUrl.toString());
      domExecuted = !!domRes.domExecuted;
      if (takeScreenshots && domRes?.screenshotBase64) {
        screenshots.push({ base64: domRes.screenshotBase64, note: domExecuted ? 'Execution evidence' : 'Page after payload inserted' });
      }
    }

    const { risk, cwe, score } = scoreRisk({ reflected, domExecuted, context });
    if (risk === 'High') high++; else if (risk === 'Medium') med++; else if (risk === 'Low') low++;
    if (domExecuted) executedCount++;

    runs.push({
      testedUrl: testUrl.toString(),
      payload: p,
      status,
      reflected,
      context,
      domExecuted,
      risk,
      cwe,
      score,
      reflection: highlighted ? { highlighted } : null,
      screenshots,
    });
  }

  // persist minimal record (optional)
  try {
    await XssTest.create({
      url,
      param,
      payloads: toTest,
      result: {
        runs: runs.slice(0, 50), // avoid huge docs
        waf: wafAgg,
        rateLimit: rateAgg,
        createdAt: new Date(),
      },
    });
  } catch (e) {
    // non-fatal
  }

  const summary = {
    total: toTest.length,
    executed: executedCount,
    high,
    medium: med,
    low,
  };

  return res.status(200).json({
    success: true,
    runs,
    waf: wafAgg,
    rateLimit: rateAgg,
    summary,
  });
};
