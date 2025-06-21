import fetch from 'node-fetch';
import { BrokenAccessScan } from '../models/brokenAccessModel.js';
import { BrokenAccessResult } from '../models/brokenAccessResultModel.js';
export const testBrokenAccessControl = async (req, res, next) => {
  try {
    const { targetUrl, authHeader, customPaths = [] } = req.body;

    if (!targetUrl || !targetUrl.startsWith('http')) {
      return res.status(400).json({ error: 'Valid targetUrl is required (must start with http/https)' });
    }

    const results = [];

    // ✅ Use default paths only if customPaths are empty
    let pathsToTest = [];

    if (customPaths && customPaths.length > 0) {
      pathsToTest = customPaths;
    } else {
      pathsToTest = customPaths;
    }

    for (const path of pathsToTest) {
      // ✅ Remove trailing slashes from targetUrl and leading slashes from path
      const fullUrl = `${targetUrl.replace(/\/+$/, '')}/${path.replace(/^\/+/, '')}`;

      // 1. Test without authentication
      try {
        const resNoAuth = await fetch(fullUrl);
        const bodyText = await resNoAuth.text();
        const sensitiveKeywords = /password|token|config|session/i;
        const hasSensitive = sensitiveKeywords.test(bodyText);

        let result = "SAFE";
        let reason = "";

        if (resNoAuth.status === 200) {
          result = "VULNERABLE";
          reason = "Endpoint accessible without authentication (200 OK)";
        } else if (resNoAuth.status === 404 && hasSensitive) {
          result = "VULNERABLE";
          reason = "Sensitive info found in 404 response body";
        }

        results.push({
          test: `Access to ${fullUrl} without authentication`,
          statusCode: resNoAuth.status,
          containsSensitiveInfo: hasSensitive,
          result,
          reason
        });
      } catch (err) {
        results.push({
          test: `Access to ${fullUrl} without authentication`,
          statusCode: 'ERROR',
          result: 'ERROR',
          errorMessage: err.message,
        });
      }

      // 2. Test with fake/real auth token if provided
      if (authHeader) {
        try {
          const resWithAuth = await fetch(fullUrl, {
            headers: { Authorization: authHeader },
          });
          const bodyText = await resWithAuth.text();
          const sensitive = /password|admin|token|user|session/i.test(bodyText);

          results.push({
            test: `Access to ${fullUrl} with Authorization`,
            statusCode: resWithAuth.status,
            containsSensitiveInfo: sensitive,
            result: resWithAuth.status === 200 || sensitive ? 'VULNERABLE' : 'SAFE',
          });
        } catch (err) {
          results.push({
            test: `Access to ${fullUrl} with Authorization`,
            statusCode: 'ERROR',
            result: 'ERROR',
            errorMessage: err.message,
          });
        }
      }
    }

     await BrokenAccessScan.create({
      targetUrl,
      customPaths,
      authHeaderUsed: !!authHeader,
      results,
     });

    req.scanResults = results;
    
    await BrokenAccessResult.create({
        targetUrl,
        results,
    });
    return res.json({ results });

  } catch (err) {
    console.error('Fatal error in Broken Access Control tester:', err);
    return res.status(500).json({ error: 'Failed to test broken access control', err: err.message });
  }
};


export const getScanHistory = async (req, res) => {
  try {
    const scans = await BrokenAccessResult.find().sort({ createdAt: -1 });
    res.json({ scans });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch scan history' });
  }
};

export const deleteScanById = async (req, res) => {
  try {
    const { id } = req.params;
    await BrokenAccessResult.findByIdAndDelete(id);
    res.json({ message: 'Scan deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete scan' });
  }
};
