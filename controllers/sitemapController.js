import { Sitemap } from "../models/sitemapModel.js";
import crawlWebsite from "../utils/crawler.js";

export const generateSitemap = async (req, res) => {
  try {
    console.log('✅ /sitemap-scanner route hit');
    console.log('Received body:', req.body);

    const { url, depth } = req.body;

    if (!url || !depth) {
      return res.status(400).json({ error: true, message: 'URL and depth are required' });
    }

    // Validate URL format
    try {
      new URL(url);
    } catch {
      return res.status(400).json({ error: true, message: 'Invalid URL format' });
    }

    const maxDepth = parseInt(depth, 10);
    if (isNaN(maxDepth) || maxDepth < 1) {
      return res.status(400).json({ error: true, message: 'Depth must be a positive integer' });
    }

    // Optional limit on depth or URL length
    if (maxDepth > 5) {
      return res.status(400).json({ error: true, message: 'Depth too large, max allowed is 5' });
    }
    if (url.length > 2048) {
      return res.status(400).json({ error: true, message: 'URL too long' });
    }

    const start = Date.now();
    const result = await crawlWebsite(url, maxDepth);
    const duration = (Date.now() - start) / 1000;
    console.log(`Crawled ${result.length} pages in ${duration}s`);

    const sitemapXml = generateXml(result);

    const newEntry = new Sitemap({
      domain: new URL(url).hostname,
      depth: maxDepth,
      urls: result,
      xml: sitemapXml,
    });

    await newEntry.save();

    return res.status(200).json({
      error: false,
      pagesFound: result.length,
      urls: result,
      xml: sitemapXml,
    });
  } catch (err) {
    console.error('Error generating sitemap:', err);
    return res.status(500).json({ error: true, message: 'Internal Server Error' });
  }
};

function escapeXml(unsafe) {
  return unsafe.replace(/[<>&'"]/g, (c) => {
    switch (c) {
      case '<': return '&lt;';
      case '>': return '&gt;';
      case '&': return '&amp;';
      case '\'': return '&apos;';
      case '"': return '&quot;';
      default: return c;
    }
  });
}

function generateXml(urls) {
  const xmlUrls = urls.map(u => `<url><loc>${escapeXml(u)}</loc></url>`).join('');
  return `<?xml version="1.0" encoding="UTF-8"?>
  <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${xmlUrls}</urlset>`;
}
