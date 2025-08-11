// controllers/wordpressController.js
import axios from 'axios';
import * as cheerio from 'cheerio';
import { WordPressScan } from '../models/wordpressModel.js';

export const scanWordPress = async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'URL is required' });

    const fullUrl = url.startsWith('http') ? url : `https://${url}`;
    const result = await performScan(fullUrl);

    if (result.notWordPress) {
      return res.status(200).json({ error: 'This is not a WordPress website.' });
    }

    await WordPressScan.create({ url: fullUrl, ...result });
    res.json(result);
  } catch (error) {
    console.error('WordPress scan error:', error.message);
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
      return { notWordPress: true };
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
    throw error;
  }
}

function checkIfWordPress($, html) {
  const generatorMeta = $('meta[name="generator"]').attr('content') || '';
  return generatorMeta.toLowerCase().includes('wordpress');
}

function extractWordPressVersion($, html) {
  const generatorMeta = $('meta[name="generator"]').attr('content') || '';
  const match = generatorMeta.match(/WordPress\s+([\d.]+)/i);
  return match ? match[1] : 'unknown';
}

function isVersionSecure(version) {
  if (version === 'unknown') return false;
  const majorVersion = parseFloat(version);
  return majorVersion >= 5.8;
}

function extractThemeInfo($) {
  const themeHref = $('link[rel="stylesheet"]').attr('href') || '';
  const match = themeHref.match(/themes\/([^\/]+)\//);
  return {
    name: match ? match[1] : 'unknown',
    version: 'unknown',
    secure: true,
  };
}

function checkCommonVulnerabilities($, html) {
  return {
    issues: [],
    vulnerablePluginsCount: 0,
    outdatedPluginsCount: 0,
  };
}

function calculateSecurityScore(result) {
  let score = 100;
  score -= result.vulnerablePlugins * 20;
  score -= result.outdatedPlugins * 10;
  if (!result.versionSecure) score -= 30;
  return Math.max(score, 0);
}
