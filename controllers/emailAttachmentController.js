export const analyzeEmailAttachment = (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: "❌ No file uploaded." });
    }

    const isSuspicious = req.file.originalname.endsWith(".exe") || req.file.size > 5 * 1024 * 1024;

    const message = isSuspicious
      ? `⚠️ Suspicious attachment detected (${req.file.originalname})`
      : `✅ ${req.file.originalname} is clean. ${score} `;

    res.json({ message });
  } catch (err) {
    res.status(500).json({ message: "❌ Server error analyzing attachment." });
  }
};
