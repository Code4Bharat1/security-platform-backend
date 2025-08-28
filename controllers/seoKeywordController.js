// controllers/keyword.controller.js
import axios from "axios";
import { load } from "cheerio";

/* ---------- helpers ---------- */
const STOP = new Set([
  "a","an","and","the","or","but","if","then","else","for","on","in","at","to","from","by",
  "of","with","without","about","as","is","are","was","were","be","been","being","it","this",
  "that","these","those","you","your","we","our","they","their","i","me","my","he","him","his",
  "she","her","hers","them","do","does","did","doing","have","has","had","having","not","no",
  "yes","can","could","should","would","will","just","than","so","such","very","more","most",
  "into","out","over","under","up","down","again","further","here","there","home","about",
  "contact","menu","search","privacy","policy","terms"
]);
const BAD = new Set(["com","www","http","https","global","assets","login","signup","cookie","cookies"]);

function titleCase(s){ return s.replace(/\b[a-z]/g, ch => ch.toUpperCase()); }

function classifyIntent(k){
  const s = k.toLowerCase();
  if (/(buy|price|agency|hire|company|services?|solutions?)/.test(s)) return "Commercial";
  if (/(best|vs|comparison|deal|quote|pricing)/.test(s)) return "Transactional";
  if (/(how|what|why|guide|tutorial|benefits|tips)/.test(s)) return "Informational";
  return "Navigational";
}

/** Extract 2–3 word phrases and counts from a block of text */
function extractPhrases(text){
  const words = text
    .toLowerCase()
    .replace(/[^a-z\s]+/g, " ")   // strip digits/ids/symbols to avoid junk like 6257adef…
    .replace(/\s+/g, " ")
    .trim()
    .split(" ")
    .filter(w => w && !STOP.has(w) && !BAD.has(w) && /^[a-z]{2,}$/.test(w));

  const counts = new Map();
  for (let i=0;i<words.length;i++){
    if (i+1<words.length){
      const p2 = `${words[i]} ${words[i+1]}`;
      if (!p2.split(" ").some(w => BAD.has(w))) counts.set(p2, (counts.get(p2)||0)+1);
    }
    if (i+2<words.length){
      const p3 = `${words[i]} ${words[i+1]} ${words[i+2]}`;
      if (!p3.split(" ").some(w => BAD.has(w))) counts.set(p3, (counts.get(p3)||0)+1);
    }
  }
  return [...counts.entries()]
    .filter(([ph]) => /^[a-z]+(?: [a-z]+){1,2}$/.test(ph))
    .sort((a,b)=> (b[1]-a[1]) || a[0].localeCompare(b[0]));
}

/** Build map: phrase -> 1-based rank (by frequency desc) */
function rankMap(items){
  const map = new Map();
  items.forEach(([p], i) => map.set(p, i+1));
  return map;
}

/* ---------- main endpoint ---------- */
export const generateKeywords = async (req, res) => {
  try {
    const { url, competitor } = req.body || {};
    if (!url) return res.status(400).json({ message: "URL is required" });

    const fetchPage = async (target) => {
      const { data: html } = await axios.get(target, {
        timeout: 40000, maxRedirects: 5,
        headers: {
          "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome Safari",
          Accept:"text/html,application/xhtml+xml"
        }
      });
      const $ = load(html);
      const text = $("body").text().replace(/\s+/g," ").trim();
      const phrases = extractPhrases(text);
      return { phrases, ranks: rankMap(phrases) };
    };

    // your site
    const { phrases: yoursPhrases, ranks: yoursRanks } = await fetchPage(url);

    // optional competitor site
    let compRanks = null, compOrigin = null;
    if (competitor) {
      ({ ranks: compRanks } = await fetchPage(competitor));
      try { compOrigin = new URL(competitor).origin; } catch {}
    }

    // keywords list (top 20 phrases)
    const keywords = yoursPhrases.slice(0, 20).map(([p]) => titleCase(p));

    // high-priority (top 6) with simple metrics
    const max = yoursPhrases[0]?.[1] || 1;
    const mkMetrics = ([p, c]) => {
      const rel = c / max;
      const difficulty = Math.max(5, Math.min(85, Math.round(25 + (1 - rel) * 50)));
      const cpc = Math.round((1 + p.split(" ").length * 0.9) * 100) / 100;
      const trend = rel >= 0.66 ? "↗" : rel <= 0.33 ? "↘" : "↔";
      return { difficulty, cpc, trend, volume: Math.round(c * 500), intent: classifyIntent(p) };
    };

    const highPriority = yoursPhrases.slice(0,6).map(([p,c])=>{
      const m = mkMetrics([p,c]);
      return {
        keyword: titleCase(p),
        volume: m.volume,
        cpc: m.cpc,
        difficulty: m.difficulty,
        trend6m: m.trend,
        intent: m.intent
      };
    });

    // long-tail (prefer trigrams), 8 rows
    const longPref = yoursPhrases
      .filter(([p]) => p.split(" ").length === 3)
      .concat(yoursPhrases.filter(([p]) => p.split(" ").length === 2));
    const longTail = longPref.slice(0,8).map(([p,c])=>{
      const m = mkMetrics([p,c]);
      return {
        keyword: titleCase(p),
        volume: m.volume,
        difficulty: m.difficulty,
        ctrPotential: `${Math.round(17 + (c/max)*6)}%`
      };
    });

    // competitor overlap (services/solutions) WITH RANKS
    const overlap = yoursPhrases
      .filter(([p]) => /(services?|solutions?)/i.test(p))
      .slice(0,6)
      .map(([p]) => ({
        keyword: titleCase(p),
        yours: yoursRanks.get(p) || "",                  // ← now a number
        competitor: compRanks ? (compRanks.get(p) || "") : "" // ← number if competitor provided
      }));

    const summary = {
      website: new URL(url).origin,
      competitor: compOrigin || null,
      date: new Date().toISOString(),
      totalKeywordsExtracted: yoursPhrases.length,
      filteredSEOKeywords: highPriority.length + longTail.length
    };

    return res.json({
      keywords,
      highPriority,
      longTail,
      overlap,
      summary,
      suggestedActions: [
        "Remove low-value keywords and noise.",
        "Create content around high-volume, lower-difficulty keywords.",
        "Optimize title/meta for top commercial-intent terms.",
        "Build backlinks targeting long-tail opportunities."
      ]
    });
  } catch (err) {
    console.error("Keyword generation error:", err?.message || err);
    res.status(500).json({ message: "Failed to generate keywords" });
  }
};
