import fetch from 'node-fetch';

export const analyzeWebsite = async (req, res) => {
  const { url } = req.body;

  // 1. Validate URL
  if (!url || typeof url !== 'string' || !url.startsWith('http')) {
    return res.status(400).json({ error: '❌ Please provide a valid website URL starting with http or https.' });
  }

  // 2. Setup API URL
  const apiKey = process.env.PAGESPEED_API_KEY;
  if (!apiKey) {
    return res.status(500).json({ error: '❌ Missing PageSpeed API key in server configuration.' });
  }

  const apiUrl = `https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=${encodeURIComponent(url)}&key=${apiKey}`;

  console.log(`📡 Sending request to Google PageSpeed API for URL: ${url}`);

  try {
    const response = await fetch(apiUrl);
    const data = await response.json();

    // 3. Handle response errors
    if (!response.ok) {
      console.error("❌ Google API Error:", JSON.stringify(data.error || data, null, 2));
      return res.status(502).json({
        error: data.error?.message || 'Failed to fetch data from Google PageSpeed API.',
        details: data.error || {}
      });
    }

    // 4. Check structure
    if (!data.lighthouseResult || !data.lighthouseResult.categories) {
      console.error("❌ Invalid response structure:", data);
      return res.status(500).json({ error: 'Invalid PageSpeed API response structure.' });
    }

    // 5. Extract scores
    const { categories } = data.lighthouseResult;
    const formatScore = (score) => typeof score === 'number' ? `${Math.round(score * 100)}/100` : 'N/A';

    const message = `
✅ Website Optimization Summary:
- 🚀 Performance: ${formatScore(categories.performance?.score)}
- ♿ Accessibility: ${formatScore(categories.accessibility?.score)}
- 🔍 SEO: ${formatScore(categories.seo?.score)}
    `.trim();

    console.log("✅ Analysis complete.");
    return res.status(200).json({ message });

  } catch (err) {
    console.error('❌ Unexpected Server Error:', err.message);
    return res.status(500).json({ error: 'Internal server error during website analysis.' });
  }
};
