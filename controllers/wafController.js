// controllers/wafController.js
import fetch from 'node-fetch';
import WafScan from '../models/wafModel.js';

const wafSigns = [
  // Cloudflare
  { header: "server", value: "cloudflare", waf: "Cloudflare" },
  { header: "cf-ray", value: "", waf: "Cloudflare" },

  // Sucuri
  { header: "x-sucuri-id", value: "", waf: "Sucuri" },
  { header: "x-sucuri-block", value: "", waf: "Sucuri" },

  // Incapsula (Imperva)
  { header: "x-iinfo", value: "", waf: "Imperva (Incapsula)" },
  { header: "x-cdn", value: "imperva", waf: "Imperva (Incapsula)" },

  // MaxCDN
  { header: "x-edge-location", value: "", waf: "MaxCDN" },
  { header: "server", value: "netdna", waf: "MaxCDN" },

  // Edgecast
  { header: "server", value: "ecs", waf: "Edgecast" },

  // Distil Networks
  { header: "x-distil-cs", value: "", waf: "Distil Networks" },
  { header: "x-distil-identify", value: "", waf: "Distil Networks" },

  // Reblaze
  { header: "rbzid", value: "", waf: "Reblaze" },
  { header: "set-cookie", value: "rbzid", waf: "Reblaze" },

  // CloudFront
  { header: "via", value: "cloudfront", waf: "CloudFront" },
  { header: "x-amz-cf-id", value: "", waf: "CloudFront" },
  { header: "server", value: "cloudfront", waf: "CloudFront" },

  // ✅ Additional WAFs
  { header: "server", value: "cloudbric", waf: "Cloudbric" },
  { header: "x-cw-cache", value: "", waf: "Comodo cWatch" },
  { header: "x-crawlprotect-id", value: "", waf: "CrawlProtect" },
  { header: "server", value: "cloudprotector", waf: "Cloud Protector" },
  { header: "server", value: "cloudfloor", waf: "Cloudfloor" },

  // ✅ Newly Added per your request
  { header: "server", value: "akamai", waf: "Akamai" },
  { header: "x-akamai-transformed", value: "", waf: "Akamai" },
  { header: "server", value: "cloudfloordns", waf: "CloudfloorDNS" },
  { header: "server", value: "cloudfirewall", waf: "Cloud Firewall" },
];

export async function detectWAF(req, res) {
  try {
    const { url } = req.body;
    if (!url) {
      return res.status(400).json({ message: 'URL is required.' });
    }

    const response = await fetch(url, { method: 'GET' });
    const headers = response.headers;
    const status = response.status;

    let detectedWAF = null;
    let matchedHeaders = [];

    for (const sign of wafSigns) {
      const headerValue = headers.get(sign.header);
      if (headerValue && (sign.value === "" || headerValue.toLowerCase().includes(sign.value))) {
        detectedWAF = sign.waf;
        matchedHeaders.push({ header: sign.header, value: headerValue });
      }
    }

    const securityHeaders = [
      "x-waf-status",
      "x-firewall",
      "x-protected-by",
      "x-sucuri-id",
      "cf-ray",
    ];

    const hasSecurityHeaders = securityHeaders.some(header => headers.has(header));
    const serverHeader = headers.get("server") || "";

    const dashboard = {
      url,
      statusCode: status,
      detected: !!detectedWAF,
      firewallName: detectedWAF || (status === 403 || status === 406 || hasSecurityHeaders || !serverHeader ? "Protected or Obfuscated" : "Not Found"),
      matchedHeaders,
      securityHeadersDetected: securityHeaders.filter(header => headers.has(header)),
      serverHeader,
      protectionLevel: status === 403 || status === 406 ? "High" : detectedWAF ? "Moderate" : "None",
    };

    // Save to DB
    const scanRecord = new WafScan({
      url,
      statusCode: status,
      detected: !!detectedWAF,
      firewallName: dashboard.firewallName,
      matchedHeaders,
      securityHeadersDetected: dashboard.securityHeadersDetected,
      serverHeader,
      protectionLevel: dashboard.protectionLevel,
      message: detectedWAF ? `Firewall Detected: ${detectedWAF}` : (dashboard.firewallName === "Protected or Obfuscated" ? "Firewall is protected" : "Firewall not found"),
    });

    await scanRecord.save();

    return res.json({
      message: scanRecord.message,
      dashboard
    });

  } catch (error) {
    return res.status(500).json({ message: 'Error: ' + error.message });
  }
}
