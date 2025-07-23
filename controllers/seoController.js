import SeoResult from '../models/seoResult.js';
import fetch from 'node-fetch';
import * as cheerio from 'cheerio';


export const analyzeSEO = async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) {
      return res.status(400).json({ message: 'URL is required' });
    }

    // Fetch HTML content of the page
    const response = await fetch(url);
    if (!response.ok) {
      return res.status(400).json({ message: 'Failed to fetch the website content' });
    }
    const html = await response.text();
    const $ = cheerio.load(html);

    // Real SEO checks
    const title = $('title').text() || null;
    const description = $('meta[name="description"]').attr('content') || null;
    const h1 = $('h1').first().text() || null;

    let score = 100;
    let issues = [];

    if (!title) {
      score -= 30;
      issues.push('Missing title tag');
    }
    if (!description) {
      score -= 30;
      issues.push('Missing meta description');
    }
    if (!h1) {
      score -= 20;
      issues.push('Missing H1 tag');
    }

    if (issues.length === 0) {
      issues.push('Good SEO health');
    }

    // ✅ Fix score: agar same URL pe dobara analyze kiya toh same score mile
    let existing = await SeoResult.findOne({ url });
    if (existing) {
      return res.json({
        message: 'SEO analysis (cached)',
        url,
        score: existing.score,
        issues: existing.issues
      });
    }

    // Save to DB
    const result = new SeoResult({ url, score, issues });
    await result.save();

    res.json({
      message: 'SEO analysis complete',
      url,
      score,
      issues
    });
  } catch (error) {
    console.error('SEO Analysis Error:', error);
    res.status(500).json({ message: 'Server error during SEO analysis' });
  }
};
