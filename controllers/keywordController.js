import * as cheerio from "cheerio";
import Keyword from "../models/keyword.model.js";

// English + technical stopwords
const STOPWORDS = new Set([
  // Common English stopwords
  "the", "and", "for", "are", "but", "with", "you", "was", "this", "that", "from",
  "have", "has", "had", "not", "all", "can", "your", "about", "they", "will", "would",
  "there", "their", "what", "when", "which", "how", "who", "our", "out", "into", "them",
  "his", "her", "she", "him", "its", "then", "been", "being", "also", "more", "some",
  "just", "any", "than", "those", "where", "why", "while", "during", "such", "each", "other",

  // Technical/code-related words
  "function", "var", "let", "const", "true", "false", "null", "return",
  "style", "script", "class", "div", "span", "width", "height", "color", "px", "1px",
  "block", "inline", "absolute", "relative", "none", "display", "margin", "padding"
]);

export const analyzeKeyword = async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ error: "URL is required" });
  }

  try {
    // Fetch page with browser-like headers to avoid blocks
    const response = await fetch(url, {
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115 Safari/537.36",
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch: ${response.status}`);
    }

    const html = await response.text();
    const $ = cheerio.load(html);

    // Remove unwanted tags to avoid code/text pollution
    $("script, style, noscript, iframe, svg, canvas").remove();

    // Get visible page text
    const text = $("body").text().replace(/\s+/g, " ").toLowerCase();
    const cleanedText = text.replace(/[^\w\s]/g, ""); // remove punctuation

    const words = cleanedText.match(/\b\w+\b/g) || [];

    // Filter stopwords and short words
    const filteredWords = words.filter(
      (word) => word.length > 2 && !STOPWORDS.has(word)
    );

    const totalWords = filteredWords.length;

    // Count single words
    const singleCounts = {};
    for (const word of filteredWords) {
      singleCounts[word] = (singleCounts[word] || 0) + 1;
    }

    // Count bigrams (2-word phrases)
    const bigramCounts = {};
    for (let i = 0; i < filteredWords.length - 1; i++) {
      const pair = `${filteredWords[i]} ${filteredWords[i + 1]}`;
      bigramCounts[pair] = (bigramCounts[pair] || 0) + 1;
    }

    const totalBigrams = Math.max(filteredWords.length - 1, 1);

    // Top 10 single words
    const singleDensity = Object.entries(singleCounts)
      .map(([phrase, count]) => ({
        phrase,
        count,
        percentage: ((count / totalWords) * 100).toFixed(2),
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    // Top 10 bigrams
    const bigramDensity = Object.entries(bigramCounts)
      .map(([phrase, count]) => ({
        phrase,
        count,
        percentage: ((count / totalBigrams) * 100).toFixed(2),
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    // Extract title and meta description
    const title = $("title").text().trim() || null;
    const metaDescription =
      $('meta[name="description"]').attr("content") || null;

    // Save or update MongoDB entry
    const existing = await Keyword.findOne({ url });
    if (existing) {
      existing.totalWords = totalWords;
      existing.singleWords = singleDensity;
      existing.phrases = bigramDensity;
      existing.title = title;
      existing.metaDescription = metaDescription;
      await existing.save();
      return res.status(200).json(existing);
    }

    const result = new Keyword({
      url,
      title,
      metaDescription,
      totalWords,
      singleWords: singleDensity,
      phrases: bigramDensity,
    });

    await result.save();
    return res.status(200).json(result);
  } catch (error) {
    console.error("Keyword analysis failed:", error.message);
    res
      .status(500)
      .json({ error: "Keyword analysis failed", details: error.message });
  }
};
