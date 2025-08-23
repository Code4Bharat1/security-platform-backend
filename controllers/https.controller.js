// controllers/httpsEnforcement.controller.js
import HttpsCheck from "../models/https.model.js";
import https from "https";
import http from "http";

/** Core security headers we expect on modern sites */
const CORE_SECURITY_HEADERS = [
  "strict-transport-security",
  "content-security-policy",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy",
];

/** Modern hardening headers (“upcoming” per your UI) */
const MODERN_HARDENING_HEADERS = [
  "cross-origin-opener-policy",      // COOP
  "cross-origin-embedder-policy",    // COEP
  "cross-origin-resource-policy",    // CORP
  "origin-agent-cluster",
  // telemetry/observability (optional; may be deprecated in some browsers)
  "report-to",
  "nel",
];

export async function checkHttpsEnforcement(req, res) {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: "Target domain is required" });

  try {
    const cleanTarget = String(target).replace(/^https?:\/\//, "").replace(/\/$/, "");

    // 1) Does http:// redirect to https:// ?
    const httpResult = await checkRedirect(`http://${cleanTarget}`);

    // 2) Grab headers from https://
    const httpsInfo = await fetchHeaders(`https://${cleanTarget}`);
    const httpsHeaders = httpsInfo.headers || {};

    // 3) HSTS parsing
    const hstsHeader = httpsHeaders["strict-transport-security"] || "";
    const hstsEnabled = !!hstsHeader;
    const maxAgeMatch = hstsHeader.match(/max-age=(\d+)/i);
    const hstsMaxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : null;
    const hstsIncludeSub = /includesubdomains/i.test(hstsHeader);
    const hstsPreload = /preload/i.test(hstsHeader);
    const hstsPreloadReady = !!(hstsEnabled && hstsIncludeSub && hstsMaxAge && hstsMaxAge >= 31536000 && hstsPreload);

    // 4) Present / Missing headers
    const present = Object.keys(httpsHeaders);
    const missingHeaders = CORE_SECURITY_HEADERS.filter(h => !(h in httpsHeaders));
    const upcomingHeaders = MODERN_HARDENING_HEADERS.filter(h => !(h in httpsHeaders));

    // 5) Additional info
    const server = httpsHeaders["server"] || null;
    const xPoweredBy = httpsHeaders["x-powered-by"] || null;
    const cacheControl = httpsHeaders["cache-control"] || null;
    const csp = httpsHeaders["content-security-policy"] || null;
    const cspReportOnly = httpsHeaders["content-security-policy-report-only"] || null;

    // quick CDN hint (best-effort)
    const cdnProvider =
      httpsHeaders["cf-ray"] ? "Cloudflare" :
      httpsHeaders["x-amz-cf-id"] || /cloudfront/i.test(httpsHeaders["via"] || "") ? "Amazon CloudFront" :
      httpsHeaders["x-akamai-transformed"] ? "Akamai" :
      httpsHeaders["x-fastly-request-id"] ? "Fastly" :
      null;

    const additionalInfo = {
      httpVersion: httpsInfo.httpVersion,                    // "2.0" / "1.1"
      tlsProtocol: httpsInfo.tls?.protocol || null,          // "TLSv1.3", etc.
      tlsCipher: httpsInfo.tls?.cipher?.name || null,        // e.g. "TLS_AES_128_GCM_SHA256"
      alpn: httpsInfo.alpn || null,                          // "h2" / "http/1.1"
      cdnProvider,
      server,
      xPoweredBy,
      cacheControl,
      csp: {
        enabled: !!csp,
        reportOnly: !!cspReportOnly,
      },
      hsts: {
        enabled: hstsEnabled,
        maxAge: hstsMaxAge,
        includeSubDomains: hstsIncludeSub,
        preload: hstsPreload,
        preloadReady: hstsPreloadReady,
      },
      redirect: {
        fromHttpStatus: httpResult.statusCode,
        location: httpResult.location || null,
        httpRedirectsToHttps: !!httpResult.redirectsToHttps,
      },
    };

    // 6) Save minimal fields (match your model)
    await HttpsCheck.create({
      target: cleanTarget,
      httpRedirectsToHttps: !!httpResult.redirectsToHttps,
      hstsEnabled,
      hstsMaxAge,
    });

    // 7) Respond enriched result
    return res.json({
      success: true,
      target: cleanTarget,
      httpRedirectsToHttps: !!httpResult.redirectsToHttps,
      hstsEnabled,
      hstsMaxAge,
      missingHeaders,
      upcomingHeaders,
      rawHeaders: httpsHeaders,      // for “Raw Headers” panel
      additionalInfo,
    });
  } catch (err) {
    console.error("HTTPS Check Error:", err);
    return res.status(500).json({
      error: "Something went wrong",
      details: err.message,
    });
  }
}

async function checkRedirect(url) {
  return new Promise((resolve) => {
    const requestModule = url.startsWith("https://") ? https : http;

    const req = requestModule.request(
      url,
      { method: "GET", timeout: 30000 }, // 30s
      (res) => {
        const isRedirect = res.statusCode >= 300 && res.statusCode < 400;
        const location = res.headers.location;
        resolve({
          redirectsToHttps: isRedirect && location && location.startsWith("https://"),
          statusCode: res.statusCode,
          location,
        });
      }
    );

    req.on("error", (err) => {
      console.error("Redirect check error:", err);
      resolve({ redirectsToHttps: false, statusCode: 0, error: err.message });
    });

    req.on("timeout", () => {
      req.destroy();
      resolve({ redirectsToHttps: false, statusCode: 0, error: "Request timeout" });
    });

    req.end();
  });
}

async function fetchHeaders(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(
      url,
      { timeout: 10000 }, // 10s
      (res) => {
        const headers = res.headers || {};
        const socket = res.socket;
        const tls = {
          protocol: typeof socket?.getProtocol === "function" ? socket.getProtocol() : null, // TLSv1.3
          cipher: typeof socket?.getCipher === "function" ? socket.getCipher() : null,       // { name, version, standardName? }
        };
        resolve({
          headers,
          httpVersion: res.httpVersion,                   // "2.0" or "1.1"
          alpn: socket?.alpnProtocol || null,             // "h2" / "http/1.1"
          tls,
        });
      }
    );

    req.on("error", (err) => {
      console.error("Headers fetch error:", err);
      reject(err);
    });

    req.on("timeout", () => {
      req.destroy();
      reject(new Error("Request timeout"));
    });
  });
}

