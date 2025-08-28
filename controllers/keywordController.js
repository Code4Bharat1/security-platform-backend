// controllers/keywordController.js
// If you're on Node 18+, you can delete this import and use global fetch.
import fetch from 'node-fetch';
import * as cheerio from 'cheerio';
import Keyword from '../models/keyword.model.js';

/**
 * POST /keyword/analyze
 * Body: {
 *   url: string,
 *   competitorUrls?: string[],
 *   targetKeywords?: string[],
 *   topN?: number,
 *   // OPTIONAL: metrics injected from your paid SEO API, if you have one:
 *   metrics?: { [keyword: string]: { searchVolume?: number, cpc?: number, difficulty?: number, trend?: 'up'|'down'|'flat' } }
 * }
 */
export const analyzeKeyword = async (req, res) => {
  const { url, competitorUrls = [], targetKeywords = [], topN = 10, metrics = {} } = req.body || {};
  if (!url) return res.status(400).json({ error: 'URL is required' });

  try {
    const normalized = normalizeUrl(url);
    const resp = await fetch(normalized, {
      headers: {
        'User-Agent':
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123 Safari/537.36',
        'Accept-Language': 'en-US,en;q=0.9',
      },
      redirect: 'follow',
    });

    if (!resp.ok) {
      return res.status(502).json({ error: `Failed to fetch: HTTP ${resp.status}` });
    }

    const html = await resp.text();
    const $ = cheerio.load(html);

    // Remove noise
    $('script, style, noscript, iframe, svg, canvas').remove();

    // On-page signals
    const title = $('title').first().text().trim() || null;
    const metaDescription = $('meta[name="description"]').attr('content') || null;
    const headings = {
      h1: $('h1').map((_, el) => $(el).text().trim()).get(),
      h2: $('h2').map((_, el) => $(el).text().trim()).get(),
      h3: $('h3').map((_, el) => $(el).text().trim()).get(),
    };
    const altTexts = $('img[alt]').map((_, el) => (($(el).attr('alt') || '').trim())).get().filter(Boolean);

    // Visible text
    const bodyText = $('body').text().replace(/\s+/g, ' ').trim();
    const { words, totalWords } = tokenize(bodyText);

    // N-grams
    const singles = countNgrams(words, 1);
    const bigrams = countNgrams(words, 2);
    const trigrams = countNgrams(words, 3);

    const topSingles   = toDensityArray(singles,  totalWords).slice(0, topN);
    const topBigrams   = toDensityArray(bigrams,  Math.max(totalWords - 1, 1)).slice(0, topN);
    const topTrigrams  = toDensityArray(trigrams, Math.max(totalWords - 2, 1)).slice(0, topN);

    // UX/SEO helpers
    const intents           = groupIntent(topSingles.map(x => x.phrase));
    const lsiSuggestions    = buildLsiSuggestions(topSingles, bigrams, trigrams, headings, altTexts);
    const overOptimization  = topSingles.filter(k => Number(k.percentage) >= 3.0)
                              .map(k => ({ keyword: k.phrase, percentage: k.percentage, flag: 'High density' }));
    const readability       = computeReadability(bodyText);
    const techSeo           = buildTechSeoChecks({ title, metaDescription, headings, altTexts, topSingles });

    // Missing keywords (from title/H1/targets)
    const mainTargets = [
      ...extractImportantWords(title),
      ...headings.h1.flatMap(extractImportantWords),
      ...targetKeywords.map(k => k.toLowerCase()),
    ];
    const missingKeywords = Array.from(new Set(mainTargets))
      .filter(k => k.length > 2 && !topSingles.some(t => t.phrase === k))
      .slice(0, 15);

    // Opportunity scores (0–100)
    const opportunity = buildOpportunityScores(topSingles, { title, headings, altTexts }).slice(0, topN);

    // Competitor summaries
    const competitorSummaries = await benchmarkCompetitors(competitorUrls, topN).catch(() => []);
    const contentLengthVerdict = benchmarkContentLength(totalWords, competitorSummaries);

    // Persist the fields your UI uses
    const existing = await Keyword.findOne({ url: normalized }).lean();
    if (existing) {
      await Keyword.updateOne(
        { _id: existing._id },
        {
          $set: {
            totalWords,
            singleWords: topSingles,
            phrases: topBigrams,
            title,
            metaDescription,
          },
        }
      );
    } else {
      await new Keyword({
        url: normalized,
        title,
        metaDescription,
        totalWords,
        singleWords: topSingles,
        phrases: topBigrams,
      }).save();
    }

    // Enhanced, “industry-style” insights (for Insight PDF)
    const insights = buildIndustryInsights({
      url: normalized,
      topSingles,
      bigrams: topBigrams,
      trigrams: topTrigrams,
      intents,
      opportunity,
      competitorSummaries,
      metrics, // plug your paid SEO metrics here if you have them
    });

    return res.json({
      url: normalized,
      title,
      metaDescription,
      totalWords,
      singleWords: topSingles,  // { phrase, count, percentage }
      phrases: topBigrams,      // bigrams
      trigrams: topTrigrams,    // extra
      headings,
      altSample: altTexts.slice(0, 20),
      intents,
      lsiSuggestions,
      overOptimization,
      readability,
      techSeo,
      missingKeywords,
      opportunity,
      benchmark: {
        competitors: competitorSummaries,
        contentLengthVerdict,
      },
      insights,                 // <— used by Insight PDF
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error('Keyword analysis failed:', err);
    return res.status(500).json({ error: 'Keyword analysis failed', details: err.message });
  }
};

/* -------------------------- Helpers -------------------------- */

const STOPWORDS = new Set([
  'the','and','for','are','but','with','you','was','this','that','from','have','has','had','not',
  'all','can','your','about','they','will','would','there','their','what','when','which','how',
  'who','our','out','into','them','his','her','she','him','its','then','been','being','also','more',
  'some','just','any','than','those','where','why','while','during','such','each','other','use','used',
  'home','about','contact','login','signup','account','dashboard',
  'function','var','let','const','true','false','null','return','style','script','class','div','span',
  'width','height','color','block','inline','absolute','relative','display','margin','padding'
]);

function normalizeUrl(u) {
  if (!/^https?:\/\//i.test(u)) return `https://${u}`;
  return u;
}

function tokenize(text) {
  const cleaned = (text || '')
    .toLowerCase()
    .replace(/[\u200B-\u200D\uFEFF]/g, '')
    .replace(/[^\w\s]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  const raw = cleaned ? cleaned.split(' ') : [];
  const words = raw.filter(w => w.length > 2 && !STOPWORDS.has(w));
  return { words, totalWords: words.length };
}

function countNgrams(words, n = 1) {
  const counts = Object.create(null);
  if (n === 1) {
    for (const w of words) counts[w] = (counts[w] || 0) + 1;
  } else {
    for (let i = 0; i <= words.length - n; i++) {
      const gram = words.slice(i, i + n).join(' ');
      counts[gram] = (counts[gram] || 0) + 1;
    }
  }
  return counts;
}

function toDensityArray(map, denom) {
  const entries = Object.entries(map).map(([phrase, count]) => ({
    phrase,
    count,
    percentage: ((count / Math.max(denom, 1)) * 100).toFixed(2),
  }));
  entries.sort((a, b) => b.count - a.count);
  return entries;
}

const INTENT = {
  transactional: ['buy','price','pricing','deal','deals','discount','coupon','order','shop','sale','subscribe','download','trial','book','reserve','quote','signup','join','get started'],
  navigational:  ['login','log in','sign in','signup','sign up','account','dashboard','contact','about','home','twitter','facebook','instagram','youtube','linkedin','github','docs','documentation'],
  informational: ['how','what','why','guide','tutorial','learn','best','top','compare','comparison','vs','review','faq','tips','ideas']
};

function groupIntent(keywords) {
  const buckets = { informational: [], transactional: [], navigational: [] };
  const look = (list, k) => list.some(w => k.includes(w));
  for (const k of keywords) {
    if (look(INTENT.transactional, k)) buckets.transactional.push(k);
    else if (look(INTENT.navigational, k))  buckets.navigational.push(k);
    else if (look(INTENT.informational, k)) buckets.informational.push(k);
    else buckets.informational.push(k);
  }
  return buckets;
}

function buildLsiSuggestions(topSingles, bigrams, trigrams, headings, altTexts) {
  const top = topSingles.slice(0, 8).map(x => x.phrase);
  const related = Object.create(null);
  for (const [gram, cnt] of Object.entries(bigrams)) {
    const [a, b] = gram.split(' ');
    if (top.includes(a)) addRel(related, a, b, cnt);
    if (top.includes(b)) addRel(related, b, a, cnt);
  }
  for (const [gram, cnt] of Object.entries(trigrams)) {
    const parts = gram.split(' ');
    for (let i = 0; i < parts.length; i++) {
      if (top.includes(parts[i])) {
        const others = parts.filter((_, j) => j !== i);
        for (const o of others) addRel(related, parts[i], o, cnt);
      }
    }
  }
  const bonusWords = [
    ...headings.h1.flatMap(extractImportantWords),
    ...headings.h2.flatMap(extractImportantWords),
    ...altTexts.flatMap(extractImportantWords),
  ];
  for (const k of Object.keys(related)) {
    related[k] = Object.entries(related[k])
      .map(([w, score]) => [w, score + (bonusWords.includes(w) ? 1 : 0)])
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([w]) => w);
  }
  return top.map(k => ({ keyword: k, related: related[k] || [] }));
}
function addRel(obj, key, word, weight = 1) {
  obj[key] = obj[key] || {};
  obj[key][word] = (obj[key][word] || 0) + weight;
}
function extractImportantWords(str = '') {
  const { words } = tokenize(str);
  return words.filter(w => w.length > 3).slice(0, 5);
}

function computeReadability(text) {
  const sentences = Math.max((text.match(/[.!?]+/g) || []).length, 1);
  const { words, totalWords } = tokenize(text);
  const syllables = words.reduce((acc, w) => acc + estimateSyllables(w), 0);
  const fkScore    = 206.835 - 1.015 * (totalWords / sentences) - 84.6 * (syllables / Math.max(totalWords, 1));
  const gradeLevel = 0.39 * (totalWords / sentences) + 11.8 * (syllables / Math.max(totalWords, 1)) - 15.59;
  const verdict    = fkScore >= 60 ? 'Easy (good for web)' : fkScore >= 30 ? 'Moderate' : 'Hard';
  return { fkScore: +fkScore.toFixed(1), gradeLevel: +gradeLevel.toFixed(1), verdict, sentences, syllables };
}
function estimateSyllables(word = '') {
  let w = word.toLowerCase();
  if (w.length <= 3) return 1;
  w = w.replace(/(?:[^laeiouy]es|ed|[^laeiouy]e)$/, '');
  w = w.replace(/^y/, '');
  const m = w.match(/[aeiouy]{1,2}/g);
  return Math.max(m ? m.length : 1, 1);
}

function buildTechSeoChecks({ title, metaDescription, headings, altTexts, topSingles }) {
  const titleLen = (title || '').length;
  const metaLen  = (metaDescription || '').length;
  const titleGood = titleLen >= 30 && titleLen <= 65;
  const metaGood  = metaLen  >= 120 && metaLen  <= 170;

  const h1Count = (headings.h1 || []).length;
  const h2Count = (headings.h2 || []).length;
  const h3Count = (headings.h3 || []).length;

  const topSet = new Set(topSingles.slice(0, 10).map(k => k.phrase));
  const h1ContainsTop  = (headings.h1 || []).some(h => containsAny(h.toLowerCase(), topSet));
  const altWithKeywords = (altTexts || []).filter(a => containsAny(a.toLowerCase(), topSet)).length;

  return {
    titleLength: titleLen,
    metaDescLength: metaLen,
    titleStatus: title ? (titleGood ? 'Good' : 'Warning') : 'Missing',
    metaDescStatus: metaDescription ? (metaGood ? 'Good' : 'Warning') : 'Missing',
    h1Count, h2Count, h3Count,
    h1ContainsTop,
    altWithKeywords,
    hasSchema: false,
  };
}
function containsAny(str, set) { for (const k of set) if (str.includes(k)) return true; return false; }

function buildOpportunityScores(topSingles, { title, headings, altTexts }) {
  const titleText = (title || '').toLowerCase();
  const hText     = [...(headings.h1 || []), ...(headings.h2 || [])].join(' ').toLowerCase();
  const altAll    = (altTexts || []).join(' ').toLowerCase();

  return topSingles.map(k => {
    const kw = k.phrase.toLowerCase();
    let score = 0;
    const density = Math.min(10, Number(k.percentage)); // cap 10%
    score += Math.max(0, 30 - density * 3);             // 0..30 inverse density
    if (titleText.includes(kw)) score += 25;
    if (hText.includes(kw))     score += 20;
    if (altAll.includes(kw))    score += 10;
    score += Math.min(35, k.count * 2);
    return {
      keyword: k.phrase,
      score: Math.round(Math.min(100, score)),
      reasons: {
        density: k.percentage,
        inTitle: titleText.includes(kw),
        inHeadings: hText.includes(kw),
        inAlt: altAll.includes(kw),
        count: k.count,
      },
    };
  }).sort((a, b) => b.score - a.score);
}

async function benchmarkCompetitors(urls = [], topN = 10) {
  const list = (urls || []).slice(0, 5);
  const out = [];
  for (const u of list) {
    try {
      const resp = await fetch(normalizeUrl(u), {
        headers: { 'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) Safari/537.36' },
        redirect: 'follow',
      });
      if (!resp.ok) continue;
      const html = await resp.text();
      const $ = cheerio.load(html);
      $('script, style, noscript, iframe, svg, canvas').remove();
      const text = $('body').text().replace(/\s+/g, ' ').trim();
      const { words, totalWords } = tokenize(text);
      const singles = countNgrams(words, 1);
      const topSingles = toDensityArray(singles, totalWords).slice(0, topN);
      out.push({
        url: normalizeUrl(u),
        totalWords,
        topKeywords: topSingles.map(k => k.phrase),
      });
    } catch { /* ignore */ }
  }
  return out;
}

function benchmarkContentLength(total, comps) {
  const avg = comps?.length
    ? Math.round(comps.reduce((a, c) => a + (c.totalWords || 0), 0) / comps.length)
    : null;
  if (!avg) return total >= 800 ? 'Likely sufficient (no comparator data)' : 'Might be thin (no comparator data)';
  if (total >= avg * 0.9) return `On par with competitors (~${avg} words)`;
  if (total >= avg * 0.6) return `Below competitor average (~${avg} words)`;
  return `Significantly below competitor average (~${avg} words)`;
}

/* ---------- Industry Insights for the Insight PDF ---------- */
function buildIndustryInsights({ url, topSingles, bigrams, trigrams, intents, opportunity, competitorSummaries, metrics }) {
  const hostname = safeHostname(url);

  const totalExtracted = (topSingles?.length || 0) + (bigrams?.length || 0) + (trigrams?.length || 0);
  const filteredSEOKeywords = topSingles.filter(k => !STOPWORDS.has(k.phrase)).length;

  const compPresence = {};
  for (const comp of competitorSummaries || []) {
    for (const kw of comp.topKeywords || []) compPresence[kw] = (compPresence[kw] || 0) + 1;
  }
  const compCount = Math.max(1, (competitorSummaries || []).length);

  const intentOf = {};
  for (const k of intents.informational) intentOf[k] = 'Informational';
  for (const k of intents.transactional) intentOf[k] = 'Commercial';
  for (const k of intents.navigational)  intentOf[k] = 'Navigational';

  const oppIndex = Object.fromEntries(opportunity.map(o => [o.keyword, o]));
  const enriched = topSingles.map(k => {
    const m = metrics[k.phrase] || {};
    const compShare = (compPresence[k.phrase] || 0) / compCount; // 0..1
    const opp = oppIndex[k.phrase]?.score ?? 0;

    const difficultyEstimate = Math.round(
      Math.min(100,
        (compShare * 60) +
        (Math.min(10, Number(k.percentage)) * 3) +
        (k.count > 5 ? 10 : 0)
      )
    );

    return {
      keyword: k.phrase,
      searchVolume: m.searchVolume ?? null,
      cpc: m.cpc ?? null,
      difficultyEstimate,
      trend: m.trend ?? 'flat',
      intent: intentOf[k.phrase] || 'Informational',
      count: k.count,
      percentage: Number(k.percentage),
      opportunityScore: opp,
      compShare,
    };
  });

  const highPriority = enriched
    .filter(e => e.intent !== 'Navigational')
    .sort((a, b) => (b.opportunityScore + (100 - b.difficultyEstimate)) - (a.opportunityScore + (100 - a.difficultyEstimate)))
    .slice(0, 8)
    .map(({ keyword, searchVolume, cpc, difficultyEstimate, trend, intent }) => ({
      keyword, searchVolume, cpc, difficulty: difficultyEstimate, trend, intent
    }));

  const longTail = enriched
    .filter(e => e.percentage < 1.2 && e.opportunityScore >= 35)
    .slice(0, 8)
    .map(e => ({
      keyword: e.keyword,
      searchVolume: metrics[e.keyword]?.searchVolume ?? null,
      difficulty: e.difficultyEstimate,
      ctrPotential: `${Math.min(30, Math.max(12, Math.round(12 + e.opportunityScore / 3)))}%`,
    }));

  const competitorOverlap = [];
  const yourRankMap = Object.fromEntries(topSingles.map((k, i) => [k.phrase, i + 1]));
  for (const comp of competitorSummaries) {
    const compRankMap = Object.fromEntries((comp.topKeywords || []).map((k, i) => [k, i + 1]));
    for (const kw of comp.topKeywords || []) {
      if (yourRankMap[kw]) {
        competitorOverlap.push({
          keyword: kw,
          rankOnYourSite: yourRankMap[kw],
          rankOnCompetitor: compRankMap[kw],
          competitorUrl: comp.url,
        });
      }
    }
  }
  competitorOverlap.sort((a, b) => a.rankOnYourSite - b.rankOnYourSite);

  const suggestedActions = [];
  if (highPriority.length) suggestedActions.push('Optimize title/meta for top 3 commercial-intent keywords.');
  if (longTail.length)     suggestedActions.push('Create content targeting long-tail opportunities.');
  if (Object.values(yourRankMap).length < 5) suggestedActions.push('Expand depth to cover more semantically related terms.');
  const highDensity = topSingles.filter(k => Number(k.percentage) >= 3);
  if (highDensity.length) suggestedActions.push('Reduce repetition on high-density terms to avoid over-optimization.');
  if (!suggestedActions.length) suggestedActions.push('Maintain balance and monitor competitors monthly.');

  return {
    header: { website: hostname, date: new Date().toISOString() },
    totals: { totalExtracted, filteredSEOKeywords },
    highPriority,
    longTail,
    competitorOverlap,
    suggestedActions,
  };
}

function safeHostname(u) { try { return new URL(u).hostname || 'site'; } catch { return 'site'; } }
