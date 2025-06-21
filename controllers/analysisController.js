// controllers/analysisController.js

import { Analysis } from "../models/analysisModel.js";
// Simulate static analysis (replace with real logic or AST parsing later)
const mockAnalyzeCode = (code) => {
  const issues = [];

  const lines = code.split('\n');
  lines.forEach((line, idx) => {
    if (line.includes('innerHTML')) {
      issues.push({
        line: idx + 1,
        snippet: line.trim(),
        message: 'Potential XSS vulnerability with innerHTML.',
      });
    } else if (line.includes('eval(')) {
      issues.push({
        line: idx + 1,
        snippet: line.trim(),
        message: 'Usage of eval is dangerous and should be avoided.',
      });
    } else if (line.includes('"SELECT') || line.includes('SELECT')) {
      issues.push({
        line: idx + 1,
        snippet: line.trim(),
        message: 'Possible SQL injection vulnerability.',
      });
    }
  });

  return issues;
};

export const analyzeCode = async (req, res) => {
  try {
    const { code } = req.body;

    if (!code || typeof code !== 'string') {
      return res.status(400).json({ error: 'Invalid code input.' });
    }

    const issues = mockAnalyzeCode(code);

    const saved = await Analysis.create({ code, issues });

    res.status(200).json({ issues });
  } catch (err) {
    console.error('Error analyzing code:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};
           