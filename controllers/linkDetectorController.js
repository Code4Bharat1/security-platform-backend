import LinkScan from "../models/LinkScan.js";

const maliciousPatterns = ["phishing", "malware", "trojan", "stealer"];
const suspiciousDomains = ["bit.ly", "tinyurl.com", "grabify.link", "shorturl.at"];

export const scanLink = async (req, res) => {
  const { url } = req.body;

  let status = "safe";
  let message = "Link appears to be safe.";

  const lowerUrl = url.toLowerCase();

  if (maliciousPatterns.some(pattern => lowerUrl.includes(pattern))) {
    status = "malicious";
    message = "This link contains known malicious patterns.";
  } else if (suspiciousDomains.some(domain => lowerUrl.includes(domain))) {
    status = "suspicious";
    message = "This link uses a suspicious or shortened domain.";
  }

  const scanResult = new LinkScan({ url, status, message });
  await scanResult.save();

  res.json({
    url,
    status,
    message,
    scannedAt: scanResult.scannedAt,
  });
};
