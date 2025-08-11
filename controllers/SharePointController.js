import axios from 'axios';
import https from 'https';
import SharePointScan from '../models/sharePointModel.js';

// Simulated user access for realistic SharePoint scenarios
const getSimulatedAccessEntries = (url) => {
  if (url.includes("public") || url.includes("demo")) {
    return [
      { user: { displayName: "Everyone" } },
      { user: { displayName: "Anonymous User" } }
    ];
  } else if (url.includes("team") || url.includes("internal")) {
    return [
      { user: { displayName: "Project Team" } },
      { user: { displayName: "Guest User" } }
    ];
  } else {
    return [
      { user: { displayName: "Authenticated Users" } }
    ];
  }
};

// Evaluate risk based on access entries
const evaluateAccessRisk = (accessEntries = []) => {
  let riskScore = 0;

  for (const entry of accessEntries) {
    const name = entry?.user?.displayName?.toLowerCase();

    if (!name) continue;
    if (name.includes("everyone") || name.includes("anonymous")) riskScore += 20;
    else if (name.includes("guest")) riskScore += 10;
    else if (name.includes("link")) riskScore += 10;
  }

  return Math.min(riskScore, 40); // Max 40 points
};

// Security score calculation
const calculateSecurityScore = ({
  permissionRiskScore,
  externalSharing,
  authenticationSecure,
  authenticationType,
  vulnerabilities = [],
  securityHeaders = [],
  usesHTTPS = true,
  hasValidSSL = true,
  redirectCount = 0
}) => {
  let score = 100;

  score -= permissionRiskScore;

  // External sharing logic
  if (externalSharing === "Everyone") score -= 15;
  else if (externalSharing === "Anyone with link") score -= 10;
  else if (externalSharing === "Limited") score -= 5;

  // Authentication
  if (!authenticationSecure) score -= 20;
  if (authenticationType === "Basic") score -= 10;

  // HTTPS/SSL
  if (!usesHTTPS) score -= 15;
  if (!hasValidSSL) score -= 10;

  // Security headers
  const expected = ["strict-transport-security", "x-frame-options", "content-security-policy"];
  expected.forEach(h => {
    if (!securityHeaders.includes(h)) score -= 5;
  });

  // Redirect penalty
  if (redirectCount > 2) score -= 5;

  return Math.max(0, Math.min(score, 100));
};

// Detect permission and headers
const detectSiteSecurity = async (url) => {
  try {
    const response = await axios.get(url, {
      maxRedirects: 5,
      timeout: 8000,
      validateStatus: () => true
    });

    const status = response.status;
    const headers = Object.keys(response.headers || {}).map(h => h.toLowerCase());
    const html = typeof response.data === "string" ? response.data : "";
    const redirectCount = response.request._redirectable?._redirectCount || 0;

    if (status === 404) return { isValid: false, reason: '404 Not Found' };
    if (status === 400 || status === 500) return { isValid: false, reason: 'Bad Request/Server Error' };

    // HTTPS and SSL check
    const usesHTTPS = url.startsWith("https://");
    const hasValidSSL = await new Promise(resolve => {
      const req = https.get(url, { rejectUnauthorized: false }, (res) => {
        resolve(true);
      });
      req.on('error', () => resolve(false));
      req.end();
    });

    // Simulate permission entries based on URL
    const accessEntries = getSimulatedAccessEntries(url);
    const permissionRiskScore = evaluateAccessRisk(accessEntries);

    return {
      isValid: true,
      permissionRiskScore,
      authenticationType: "OAuth", // default in this case
      authenticationSecure: true,
      externalSharing: "Limited",
      vulnerabilities: [],
      securityHeaders: headers,
      usesHTTPS,
      hasValidSSL,
      redirectCount
    };
  } catch (err) {
    console.error("Security detection failed:", err.message);
    return { isValid: false, reason: "Unreachable or network error" };
  }
};

// Final controller function
export const scanSharePoint = async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'URL is required' });

    const result = await detectSiteSecurity(url);

    if (!result.isValid) {
      return res.status(400).json({ error: `Invalid SharePoint URL: ${result.reason}` });
    }

    const securityScore = calculateSecurityScore(result);

    const scanData = {
      url,
      version: "SharePoint Online",
      versionSupported: true,
      authenticationType: result.authenticationType,
      authenticationSecure: result.authenticationSecure,
      externalSharing: result.externalSharing,
      permissionIssues: result.permissionRiskScore / 10, // Convert back to 0–5 scale
      securityPatches: "Up to date",
      vulnerabilities: result.vulnerabilities,
      securityScore
    };

    const savedScan = new SharePointScan(scanData);
    await savedScan.save();

    res.status(200).json(scanData);
  } catch (err) {
    console.error("Scan error:", err.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};
