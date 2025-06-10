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

    const result = await crawlWebsite(url, depth);
    
    const sitemapXml = generateXml(result); // Convert to XML

    const newEntry = new Sitemap({
      domain: new URL(url).hostname,
      depth,
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
    console.error(err);
    return res.status(500).json({ error: true, message: 'Internal Server Error' });
  }
};

function generateXml(urls) {
  const xmlUrls = urls.map(u => `<url><loc>${u}</loc></url>`).join('');
  return `<?xml version="1.0" encoding="UTF-8"?>
  <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${xmlUrls}</urlset>`;
}
