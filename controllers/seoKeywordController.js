import axios from 'axios';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const cheerio = require('cheerio');
const keyword_extractor = require('keyword-extractor');

export const generateKeywords = async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ message: "URL is required" });

    // 1️⃣ Fetch page
    const response = await axios.get(url);
    const html = response.data;

    // 2️⃣ Extract text
    const $ = cheerio.load(html);
    const text = $('body').text();

    // 3️⃣ Extract keywords
    const keywords = keyword_extractor.extract(text, {
      language: "english",
      remove_digits: true,
      return_changed_case: true,
      remove_duplicates: true
    });

    // 4️⃣ Return top 20 unique keywords
    const topKeywords = keywords.slice(0, 20);

    res.json({ keywords: topKeywords });
  } catch (err) {
    console.error('Keyword generation error:', err);
    res.status(500).json({ message: 'Failed to generate keywords' });
  }
};
