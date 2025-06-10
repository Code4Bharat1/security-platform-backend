
import * as cheerio from "cheerio";
import Keyword from "../models/keyword.model.js";

const STOPWORDS = new Set([
  "the",
  "and",
  "for",
  "are",
  "but",
  "with",
  "you",
  "was",
  "this",
  "that",
  "from",
  "have",
  "has",
  "had",
  "not",
  "all",
  "can",
  "your",
  "about",
  "they",
  "will",
  "would",
  "there",
  "their",
  "what",
  "when",
  "which",
  "how",
  "who",
  "our",
  "out",
  "into",
  "them",
  "his",
  "her",
  "she",
  "him",
  "its",
  "then",
  "been",
  "being",
  "also",
]);

export const analyzeKeyword = async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ error: "URL is required" });
  }
       
  try {
    const response = await fetch(url);
    const html = await response.text();

    const $ = cheerio.load(html);
    const text = $("body").text().replace(/\s+/g, " ").toLowerCase();

    const words = text.match(/\b\w+\b/g) || [];
    const filteredWords = words.filter(
      (word) => word.length > 2 && !STOPWORDS.has(word)
    );
    const totalWords = filteredWords.length;

    const singleCounts = {};
    filteredWords.forEach((word) => {
      singleCounts[word] = (singleCounts[word] || 0) + 1;
    });

    const bigramCounts = {};
    for (let i = 0; i < filteredWords.length - 1; i++) {
      const pair = `${filteredWords[i]} ${filteredWords[i + 1]}`;
      bigramCounts[pair] = (bigramCounts[pair] || 0) + 1;
    }

    const singleDensity = Object.entries(singleCounts)
      .map(([phrase, count]) => ({
        phrase,
        count,
        percentage: ((count / totalWords) * 100).toFixed(2),
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    const bigramDensity = Object.entries(bigramCounts)
      .map(([phrase, count]) => ({
        phrase,
        count,
        percentage: ((count / totalWords) * 100).toFixed(2),
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    // Save result to MongoDB
    const result = new Keyword({
      url,
      totalWords,
      singleWords: singleDensity,
      phrases: bigramDensity,
    });

    await result.save();

    res.status(200).json(result);
  } catch (error) {
    console.error("Keyword analysis failed:", error);
    res.status(500).json({ error: "Fetch failed", details: error.message });
  }
};
