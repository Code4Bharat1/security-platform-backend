import SharePointScan from '../models/sharePointModel.js';

const simulateScan = (url) => {
  const version = "SharePoint Online";
  const versionSupported = true;
  const authenticationType = "OAuth";
  const authenticationSecure = true;
  const externalSharing = "Limited";
  const permissionIssues = Math.floor(Math.random() * 6);
  const securityPatches = "Up to date";
  const vulnerabilities = permissionIssues > 3 ? ["Over-permissive roles", "Missing MFA"] : [];
  const securityScore = 85 - permissionIssues * 5;

  return {
    url,
    version,
    versionSupported,
    authenticationType,
    authenticationSecure,
    externalSharing,
    permissionIssues,
    securityPatches,
    vulnerabilities,
    securityScore,
  };
};

export const scanSharePoint = async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'URL is required' });

    const result = simulateScan(url);
    const savedScan = new SharePointScan(result);
    await savedScan.save();

    res.status(200).json(result);
  } catch (err) {
    console.error('Error scanning SharePoint site:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};
