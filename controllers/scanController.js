// ===== controllers/scanController.js =====
import sslChecker from 'ssl-checker';
import axios from 'axios';
import https from 'https';
import ScanResult from '../models/scanResultModel.js'; // Ensure the path is correct
export const runScan = async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required.' });

  try {
    const domain = url.replace(/^https?:\/\//, '').split('/')[0];
    const formattedUrl = `https://${domain}`;

    const scanResults = {
      domain,
      timestamp: new Date().toISOString(),
      ssl: null,
      headers: null,
      openPorts: null,
      vulnerabilities: []
    };

    try {
      scanResults.ssl = await sslChecker(domain);
    } catch (error) {
      scanResults.vulnerabilities.push({
        type: 'ssl',
        severity: 'high',
        description: 'SSL certificate issue detected',
        details: error.message
      });
    }

    try {
      const agent = new https.Agent({ rejectUnauthorized: false });
      const response = await axios.get(formattedUrl, {
        timeout: 5000,
        httpsAgent: agent,
        validateStatus: () => true
      });

      const headers = response.headers;
      scanResults.headers = headers;

      const securityHeaders = {
        'strict-transport-security': 'Strict Transport Security not configured',
        'content-security-policy': 'Content Security Policy not configured',
        'x-content-type-options': 'X-Content-Type-Options not configured',
        'x-frame-options': 'X-Frame-Options not configured',
        'x-xss-protection': 'X-XSS-Protection not configured'
      };

      for (const [header, message] of Object.entries(securityHeaders)) {
        if (!headers[header]) {
          scanResults.vulnerabilities.push({
            type: 'header',
            severity: 'medium',
            description: message,
            recommendation: `Add the ${header} header to enhance security`
          });
        }
      }

      if (headers.server) {
        scanResults.vulnerabilities.push({
          type: 'information_disclosure',
          severity: 'low',
          description: 'Server information disclosure',
          details: `Server header reveals: ${headers.server}`,
          recommendation: 'Hide server information in HTTP headers'
        });
      }

    } catch (error) {
      scanResults.vulnerabilities.push({
        type: 'connection',
        severity: 'medium',
        description: 'Failed to connect or retrieve headers',
        details: error.message
      });
    }

    const commonPaths = [
      '/.git/config', '/.env', '/wp-config.php', '/phpinfo.php',
      '/admin', '/config', '/backup', '/wp-admin', '/server-status'
    ];

    for (const path of commonPaths) {
      try {
        const response = await axios.get(`${formattedUrl}${path}`, {
          timeout: 3000,
          httpsAgent: new https.Agent({ rejectUnauthorized: false }),
          validateStatus: () => true
        });

        if (response.status === 200) {
          scanResults.vulnerabilities.push({
            type: 'exposure',
            severity: 'high',
            description: 'Potentially sensitive resource exposed',
            details: `${path} is accessible (Status: ${response.status})`,
            recommendation: 'Restrict access to this resource'
          });
        }
      } catch (_) {
        // Ignore unreachable paths
      }
    }

    scanResults.vulnerabilityCount = scanResults.vulnerabilities.length;
    scanResults.riskLevel = scanResults.vulnerabilityCount > 5 ? 'high'
                                : scanResults.vulnerabilityCount > 2 ? 'medium' : 'low';

    const saved = await ScanResult.create(scanResults);
    return res.status(200).json(saved);

  } catch (error) {
    return res.status(500).json({ error: 'Failed to complete vulnerability scan', message: error.message });
  }
};