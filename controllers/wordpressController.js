import axios from 'axios';
import * as cheerio from 'cheerio';

import { WordPressScan } from '../models/wordpressModel.js';

export const scanWordPress = async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'URL is required' });

    const fullUrl = url.startsWith('http') ? url : `https://${url}`;
    const result = await performScan(fullUrl);

    // Save scan result in DB (optional)
    await WordPressScan.create({ url: fullUrl, ...result });

    res.json(result);
  } catch (error) {
    console.error('WordPress scan error:', error.message);
    console.error(error.stack);
    res.status(500).json({ error: 'Failed to scan WordPress site' });
  }
};

async function performScan(url) {
  try {
    const response = await axios.get(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; WPSecurityScanner/1.0)',
      },
      timeout: 10000,
    });

    const html = response.data;
    const $ = cheerio.load(html);

    if (!checkIfWordPress($, html)) {
      throw new Error('Not a WordPress site');
    }

    const version = extractWordPressVersion($, html);
    const result = {
      version,
      versionSecure: isVersionSecure(version),
      theme: extractThemeInfo($),
      vulnerablePlugins: 0,
      outdatedPlugins: 0,
      securityScore: 0,
      issues: [],
    };

    const vulns = checkCommonVulnerabilities($, html);
    result.issues = vulns.issues;
    result.vulnerablePlugins = vulns.vulnerablePluginsCount;
    result.outdatedPlugins = vulns.outdatedPluginsCount;

    result.securityScore = calculateSecurityScore(result);

    return result;
  } catch (error) {
    console.error('performScan error:', error.message);
    throw error;
  }
}

function checkIfWordPress($, html) {
  const generatorMeta = $('meta[name="generator"]').attr('content') || '';
  return generatorMeta.toLowerCase().includes('wordpress');
}

// Placeholder utility functions — implement these based on your logic

function extractWordPressVersion($, html) {
  const generatorMeta = $('meta[name="generator"]').attr('content') || '';
  const match = generatorMeta.match(/WordPress\s+([\d.]+)/i);
  return match ? match[1] : 'unknown';
}

function isVersionSecure(version) {
  // Example: return false if version < 5.8
  if (version === 'unknown') return false;
  const majorVersion = parseFloat(version);
  return majorVersion >= 5.8;
}

function extractThemeInfo($) {
  // Example: look for theme stylesheet URL or meta tag
  const themeHref = $('link[rel="stylesheet"]').attr('href') || '';
  const match = themeHref.match(/themes\/([^\/]+)\//);
  return match ? match[1] : 'unknown';
}

function checkCommonVulnerabilities($, html) {
  // Dummy implementation, replace with actual logic
  return {
    issues: [],
    vulnerablePluginsCount: 0,
    outdatedPluginsCount: 0,
  };
}

function calculateSecurityScore(result) {
  // Dummy scoring logic
  let score = 100;
  score -= result.vulnerablePlugins * 20;
  score -= result.outdatedPlugins * 10;
  if (!result.versionSecure) score -= 30;
  return Math.max(score, 0);
}
