import SeoResult from '../models/seoResult.js';
import fetch from 'node-fetch';
import * as cheerio from 'cheerio';
import dns from 'dns';

export const analyzeSEO = async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) {
      return res.status(400).json({ message: 'URL is required' });
    }

    // Fetch HTML content
    const response = await fetch(url, { timeout: 15000 });
    if (!response.ok) {
      return res.status(400).json({ message: 'Failed to fetch the website content' });
    }

    const html = await response.text();
    const $ = cheerio.load(html);

    // Extract SEO elements
    const title = $('title').text().trim() || "N/A";
    const description = $('meta[name="description"]').attr('content') || "N/A";
    const h1 = $('h1').first().text().trim() || "N/A";
    const canonical = $('link[rel="canonical"]').attr('href') || "N/A";
    const robots = $('meta[name="robots"]').attr('content') || "N/A";
    const imagesWithoutAlt = $('img:not([alt])').length;

    // Page size (KB)
    const pageSizeKB = (Buffer.byteLength(html, 'utf8') / 1024).toFixed(2);

    // Initial Score
    let score = 100;
    let issues = [];
    let strengths = [];

    if (title === "N/A") { score -= 20; issues.push('Missing <title> tag'); } else { strengths.push('Title tag present'); }
    if (description === "N/A") { score -= 15; issues.push('Missing meta description'); } else { strengths.push('Meta description present'); }
    if (h1 === "N/A") { score -= 10; issues.push('Missing H1 tag'); } else { strengths.push('H1 tag present'); }
    if (canonical === "N/A") { score -= 5; issues.push('Missing canonical tag'); } else { strengths.push('Canonical tag present'); }
    if (robots === "N/A") { score -= 5; issues.push('Missing robots meta tag'); } else { strengths.push('Robots meta tag present'); }
    if (imagesWithoutAlt > 0) { score -= 10; issues.push(`${imagesWithoutAlt} images missing ALT attributes`); } else { strengths.push('All images have ALT attributes'); }

    if (pageSizeKB > 1024) { score -= 10; issues.push('Page size is too large (>1MB)'); }
    else { strengths.push('Good page size'); }

    if (score < 0) score = 0;

    // Mobile friendly check
    const viewport = $('meta[name="viewport"]').attr('content');
    const mobileFriendly = viewport ? true : false;
    if (!mobileFriendly) {
      score -= 10;
      issues.push('Missing viewport meta tag (Not mobile-friendly)');
    } else {
      strengths.push('Mobile-friendly detected');
    }

    // DNS lookup
    let dnsResolved = true;
    await new Promise((resolve) => {
      dns.lookup(new URL(url).hostname, (err) => {
        if (err) {
          dnsResolved = false;
          issues.push('DNS lookup failed');
          score -= 10;
        } else {
          strengths.push('DNS lookup successful');
        }
        resolve();
      });
    });

    // Check if already cached
    let existing = await SeoResult.findOne({ url });
    if (existing) {
      return res.json({
        message: 'SEO analysis (cached)',
        url,
        score: existing.score,
        title: existing.title,
        description: existing.description,
        h1: existing.h1,
        canonical: existing.canonical,
        robots: existing.robots,
        issues: existing.issues,
        strengths: existing.strengths,
        pageSizeKB: existing.pageSizeKB,
        mobileFriendly: existing.mobileFriendly,
      });
    }

    // Save result
    const result = new SeoResult({
      url,
      score,
      title,
      description,
      h1,
      canonical,
      robots,
      issues,
      strengths,
      pageSizeKB,
      mobileFriendly
    });
    await result.save();

    // Response
    res.json({
      message: 'SEO analysis complete',
      url,
      score,
      title,
      description,
      h1,
      canonical,
      robots,
      issues,
      strengths,
      pageSizeKB,
      mobileFriendly
    });
  } catch (error) {
    console.error('SEO Analysis Error:', error);
    res.status(500).json({ message: 'Server error during SEO analysis' });
  }
};
