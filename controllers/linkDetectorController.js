import LinkScan from "../models/LinkScan.js";
import fetch from "node-fetch"; // ✅ make sure to install: npm i node-fetch@2

const maliciousPatterns = ["phishing", "malware", "trojan", "stealer"];
const suspiciousDomains = ["bit.ly", "tinyurl.com", "grabify.link", "shorturl.at"];

export const scanLink = async (req, res) => {
  const { url } = req.body;
  let status = "safe";
  let message = "Link appears to be safe.";

  try {
    const lowerUrl = url.toLowerCase();

    // ✅ 1. Check for known malicious patterns
    if (maliciousPatterns.some(pattern => lowerUrl.includes(pattern))) {
      status = "malicious";
      message = "This link contains known malicious patterns.";
    } 
    // ✅ 2. Check suspicious / shortened domains
    else if (suspiciousDomains.some(domain => lowerUrl.includes(domain))) {
      status = "suspicious";
      message = "This link uses a suspicious or shortened domain.";
    } 
    else {
      // ✅ 3. Actually check if URL exists by sending HEAD request
      const response = await fetch(url, { method: "HEAD", timeout: 5000 });

      if (!response.ok) {
        status = "invalid";
        message = `Link responded with status code: ${response.status}`;
      } else {
        status = "safe";
        message = "Link is reachable and seems safe.";
      }
    }

    const scanResult = new LinkScan({ url, status, message });
    await scanResult.save();

    res.json({
      url,
      status,
      message,
      scannedAt: scanResult.scannedAt,
    });

  } catch (error) {
    console.error("Link scan error:", error);
    res.status(500).json({ message: "Server error during link scan." });
  }
};
