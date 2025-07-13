import SeoResult from '../models/seoResult.js';

export const analyzeSEO = async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) {
      return res.status(400).json({ message: 'URL is required' });
    }

    // Dummy logic: random score between 50-100
    const score = Math.floor(Math.random() * 50) + 50;

    let issues = [];
    if (score < 60) {
      issues.push('Major SEO issues detected');
    } else if (score < 80) {
      issues.push('Some improvements needed');
    } else {
      issues.push('Good SEO health');
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
