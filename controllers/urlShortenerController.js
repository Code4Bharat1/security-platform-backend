import ShortUrl from '../models/ShortUrl.js';

export const createShortUrl = async (req, res) => {
  try {
    const { originalUrl } = req.body;
    if (!originalUrl) return res.status(400).json({ message: "URL is required" });

    // Generate random short code
    const shortCode = Math.random().toString(36).substring(2, 8);

    const newUrl = new ShortUrl({ originalUrl, shortCode });
    await newUrl.save();

    // ✅ Best: return only the code
    res.json({ code: shortCode });
  } catch (err) {
    console.error('Shorten Error:', err);
    res.status(500).json({ message: 'Server error' });
  }
};

export const redirectToOriginalUrl = async (req, res) => {
  try {
    const { code } = req.params;
    const urlDoc = await ShortUrl.findOne({ shortCode: code });
    if (urlDoc) {
      return res.redirect(urlDoc.originalUrl);
    } else {
      return res.status(404).json({ message: 'URL not found' });
    }
  } catch (err) {
    console.error('Redirect Error:', err);
    res.status(500).json({ message: 'Server error' });
  }
};
