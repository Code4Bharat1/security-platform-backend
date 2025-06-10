// controllers/codeObfuscationController.js
import { CodeObfuscation } from '../models/codeObfuscationModel.js';

// Utility functions for simple checks (example heuristics)
const detectShortVariables = (code) => {
  // Very naive example: find variable names of length <= 2
  const regex = /\b(var|let|const)\s+([a-zA-Z_$]{1,2})\b/g;
  const shortVars = [];
  let match;
  while ((match = regex.exec(code)) !== null) {
    shortVars.push(match[2]);
  }
  return [...new Set(shortVars)]; // unique
};

const detectEncodedStrings = (code) => {
  // Look for long base64 strings or hex encoded strings (simple)
  const base64Regex = /['"`]([A-Za-z0-9+/=]{20,})['"`]/g;
  const matches = code.match(base64Regex);
  return matches ? matches.length : 0;
};

const detectUsesEval = (code) => {
  return /\beval\s*\(/.test(code);
};

const calculateSeverity = ({ shortVars, encodedStringsCount, usesEval }) => {
  // Simplified scoring system:
  let score = 0;
  if (shortVars.length > 5) score += 2;
  else if (shortVars.length > 0) score += 1;
  if (encodedStringsCount > 2) score += 2;
  else if (encodedStringsCount > 0) score += 1;
  if (usesEval) score += 3;

  if (score >= 5) return 'High';
  if (score >= 2) return 'Medium';
  return 'Low';
};

export const analyzeCodeObfuscation = async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) {
      return res.status(400).json({ error: 'Code is required' });
    }

    const shortVars = detectShortVariables(code);
    const encodedStringsCount = detectEncodedStrings(code);
    const usesEval = detectUsesEval(code);
    const severity = calculateSeverity({ shortVars, encodedStringsCount, usesEval });

    // Optionally save result to DB
    const analysis = new CodeObfuscation({
      code,
      severity,
      shortVars,
      encodedStringsCount,
      usesEval
    });
    await analysis.save();

    res.json({
      severity,
      shortVars,
      encodedStrings: new Array(encodedStringsCount).fill('encodedString'),
      usesEval
    });
  } catch (error) {
    console.error('Error analyzing code:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};
