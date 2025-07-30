import DataLeakResult from "../models/dataLeakResult.js";

const sensitivePatterns = [
  /api[_-]?key[\s:=]*[a-z0-9]{16,}/i,        // API keys
  /bearer\s+[a-z0-9\-_\.=]+/i,               // Bearer tokens
  /[\w.-]+@[\w.-]+\.\w+/g,                   // Emails
  /(?:\d[ -]*?){13,16}/g,                    // Credit card-like numbers
  /password\s*[:=]\s*['"]?.{4,}/i            // Password-like fields
];

export const detectDataLeak = async (req, res) => {
  try {
    const files = req.files;

    if (!files || files.length === 0) {
      return res.status(400).json({ message: "No files uploaded" });
    }

    const sensitiveMatches = new Set();
    let totalLinesScanned = 0;

    for (const file of files) {
      const content = file.buffer.toString("utf-8");
      const lines = content.split("\n");
      totalLinesScanned += lines.length;

      lines.forEach(line => {
        for (const pattern of sensitivePatterns) {
          const match = line.match(pattern);
          if (match) {
            sensitiveMatches.add(match[0]);
          }
        }
      });

      const result = new DataLeakResult({
        filename: file.originalname,
        totalLinesScanned: lines.length,
        sensitiveMatches: [...sensitiveMatches]
      });

      await result.save();
    }

    const message =
      sensitiveMatches.size > 0
        ? `⚠️ ${sensitiveMatches.size} sensitive pattern(s) detected. ${score} `
        : "✅ No sensitive data found.";

    res.status(200).json({
      message,
      totalLinesScanned,
      sensitiveMatches: [...sensitiveMatches]
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Data leak detection failed", error: err.message });
  }
};
