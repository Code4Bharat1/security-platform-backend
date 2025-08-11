import HttpsCheck from "../models/https.model.js";
import https from "https";
import http from "http"; // Add this import

export async function checkHttpsEnforcement(req, res) {
  const { target } = req.body;

  if (!target)
    return res.status(400).json({ error: "Target domain is required" });

  try {
    // Clean the target URL (remove protocol if provided)
    const cleanTarget = target.replace(/^https?:\/\//, "");

    const httpResult = await checkRedirect(`http://${cleanTarget}`);
    const httpsHeaders = await fetchHeaders(`https://${cleanTarget}`);

    const hstsHeader = httpsHeaders["strict-transport-security"] || "";
    const hstsEnabled = hstsHeader !== "";
    const maxAgeMatch = hstsHeader.match(/max-age=(\d+)/);
    const hstsMaxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : null;

    await HttpsCheck.create({
      target: cleanTarget,
      httpRedirectsToHttps: httpResult.redirectsToHttps,
      hstsEnabled,
      hstsMaxAge,
    });

    res.json({
      success: true,
      target: cleanTarget,
      httpRedirectsToHttps: httpResult.redirectsToHttps,
      hstsEnabled,
      hstsMaxAge,
    });
  } catch (err) {
    console.error("HTTPS Check Error:", err);
    res.status(500).json({
      error: "Something went wrong",
      details: err.message,
    });
  }
}

async function checkRedirect(url) {
  return new Promise((resolve) => {
    // Use http module for http:// URLs
    const requestModule = url.startsWith("https://") ? https : http;

    const req = requestModule.request(
      url,
      {
        method: "GET",
        timeout: 30000, // 30 second timeout
        // Follow redirects manually to check if they go to HTTPS
        followRedirect: false,
      },
      (res) => {
        const isRedirect = res.statusCode >= 300 && res.statusCode < 400;
        const redirectsToHttps =
          isRedirect &&
          res.headers.location &&
          res.headers.location.startsWith("https://");

        resolve({
          redirectsToHttps,
          statusCode: res.statusCode,
          location: res.headers.location,
        });
      }
    );

    req.on("error", (err) => {
      console.error("Redirect check error:", err);
      resolve({ redirectsToHttps: false, error: err.message });
    });

    req.on("timeout", () => {
      req.destroy();
      resolve({ redirectsToHttps: false, error: "Request timeout" });
    });

    req.end();
  });
}

async function fetchHeaders(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(
      url,
      {
        timeout: 10000, // 10 second timeout
      },
      (res) => {
        resolve(res.headers);
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
