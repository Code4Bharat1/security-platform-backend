// controllers/analyzeCodeController.js

import { CodeAnalysis } from "../models/analyzeCodeModel.js";
export const analyzeCode = async (req, res) => {
  const { code } = req.body;

  if (!code || typeof code !== 'string') {
    return res.status(400).json({ error: 'Code must be a string.' });
  }

  const resultsArray = [];
  let passed = 0;
  let failed = 0;

  const lines = code.split('\n');

  lines.forEach((line, index) => {
    const trimmed = line.trim().toLowerCase();
    const lineNumber = index + 1;

    if (trimmed.includes('eval(')) {
      resultsArray.push(`Line ${lineNumber}: Avoid using eval().`);
      failed++;
    } else if (trimmed.includes('document.write')) {
      resultsArray.push(`Line ${lineNumber}: Avoid using document.write().`);
      failed++;
    } else if (trimmed.includes('innerhtml')) {
      resultsArray.push(`Line ${lineNumber}: Avoid using innerHTML.`);
      failed++;
    } else {
      passed++;
    }
  });

  const resultDoc = {
    message: "Code analysis completed successfully.",
    passed,
    failed,
    results: resultsArray,
  };

  try {
    // ✅ Save the full document including subdocument
    const saved = await CodeAnalysis.create({
      code,
      results: resultDoc,
      lines: lines.length,
      fileLength: code.length,
    });

    console.log("✅ Analysis saved with ID:", saved._id);

    res.status(200).json(resultDoc);
  } catch (error) {
    console.error("❌ DB Save Error:", error.message);
    res.status(500).json({ error: "Failed to save analysis result." });
  }
};
