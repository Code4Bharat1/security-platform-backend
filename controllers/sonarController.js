// controllers/sonarController.js
import { SonarResult } from '../models/sonarModel.js';

export const analyzeCode = async (req, res) => {
  const { code } = req.body;

  if (!code || typeof code !== 'string') {
    return res.status(400).json({ error: 'Invalid or missing code.' });
  }
       
  try {
    const issues = [];
    const lines = code.split('\n');

    lines.forEach((rawLine, index) => {
      const line = rawLine.toLowerCase();
      const lineNumber = index + 1;

      // Unsafe JavaScript patterns
      if (line.includes('eval(')) {
        issues.push({ line: lineNumber, message: 'Avoid using eval().' });
      }

      if (line.includes('document.write')) {
        issues.push({ line: lineNumber, message: 'Avoid using document.write().' });
      }

      if (line.includes('innerhtml')) {
        issues.push({ line: lineNumber, message: 'Avoid assigning directly to innerHTML (XSS risk).' });
      }

      if (line.includes('settimeout("') || line.includes("settimeout('")) {
        issues.push({ line: lineNumber, message: 'Avoid passing strings to setTimeout (acts like eval).' });
      }

      if (line.includes('setinterval("') || line.includes("setinterval('")) {
        issues.push({ line: lineNumber, message: 'Avoid passing strings to setInterval (acts like eval).' });
      }

      // Inline event handlers
      if (
        line.includes('onclick') ||
        line.includes('onload') ||
        line.includes('onerror') ||
        line.includes('onmouseover') ||
        line.includes('setattribute("onclick') ||
        line.includes("setattribute('onclick")
      ) {
        issues.push({ line: lineNumber, message: 'Avoid using inline event handlers like onclick, onload, etc.' });
      }

      // Script injection
      if (
        line.includes('createelement("script') ||
        line.includes("createelement('script")
      ) {
        issues.push({ line: lineNumber, message: 'Suspicious dynamic script injection detected.' });
      }
    });

    // Save results to DB
    await SonarResult.create({ code, issues });

    // Send response
    return res.json({ issues });
  } catch (err) {
    console.error('Analysis error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};
