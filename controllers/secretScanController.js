import { SecretScan } from '../models/secretScanModel.js';

// Example regex rules for demonstration
const rules = [
  {
    type: 'AWS Secret Key',
    regex: /aws_secret_access_key\s*=\s*["']?([A-Za-z0-9\/+=]{40})["']?/,
    severity: 'Critical',
    suggestion: 'Revoke and rotate this key immediately.',
  },
  {
    type: 'JWT Secret',
    regex: /jwt[_-]?secret\s*=\s*["'](.{8,})["']/i,
    severity: 'High',
    suggestion: 'Use environment variables instead.',
  },
  {
    type: 'Generic API Key',
    regex: /api[_-]?key\s*=\s*["']?([\w-]{16,})["']?/i,
    severity: 'Medium',
    suggestion: 'Avoid hardcoding API keys in code.',
  },
];

export const scanSecretKeys = async (req, res) => {
  const { code } = req.body;

  if (!code) {
    return res.status(400).json({ error: 'Code is required for scanning.' });
  }

  try {
    const lines = code.split('\n');
    const secrets = [];

    lines.forEach((lineText, index) => {
      rules.forEach((rule) => {
        const match = lineText.match(rule.regex);
        if (match) {
          secrets.push({
            type: rule.type,
            line: index + 1,
            secret: match[1],
            severity: rule.severity,
            suggestion: rule.suggestion,
          });
        }
      });
    });

    // Save to MongoDB
    await SecretScan.create({
      code,
      results: secrets,
    });

    res.status(200).json({ secrets });
  } catch (err) {
    console.error('Secret scan error:', err.message);
    res.status(500).json({ error: 'Failed to scan secrets.', details: err.message });
  }
};
