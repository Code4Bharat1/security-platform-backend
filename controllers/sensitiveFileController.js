import fetch from 'node-fetch';
import { SensitiveFileScan } from '../models/sensitiveFileModel.js';

const sensitivePaths = [
  { path: '.env', expectedPublic: false, riskLevel: 'high' },
  { path: '.git/', expectedPublic: false, riskLevel: 'high' },
  { path: '.htaccess', expectedPublic: false, riskLevel: 'high' },
  { path: '.DS_Store', expectedPublic: false, riskLevel: 'moderate' },
  { path: 'backup.zip', expectedPublic: false, riskLevel: 'high' },
  { path: 'config.php', expectedPublic: false, riskLevel: 'high' },
  { path: 'composer.lock', expectedPublic: true, riskLevel: 'moderate' },
  { path: 'yarn.lock', expectedPublic: true, riskLevel: 'moderate' },
  { path: 'package-lock.json', expectedPublic: true, riskLevel: 'moderate' },
  { path: 'package.json', expectedPublic: true, riskLevel: 'moderate' },
  { path: 'credentials.txt', expectedPublic: false, riskLevel: 'high' },
  { path: '.ftpconfig', expectedPublic: false, riskLevel: 'moderate' },
  { path: 'phpinfo.php', expectedPublic: false, riskLevel: 'high' },
  { path: 'db.sql', expectedPublic: false, riskLevel: 'high' },
];


export const checkSensitiveFiles = async (req, res) => {
  const { url } = req.body;

  if (!url || !url.startsWith('http')) {
    return res.status(400).json({ error: 'Invalid URL' });
  }

  const results = [];

  for (const file of sensitivePaths) {
    const target =  `${url.replace(/\/$/, '')}/${file.path}`;
    try {
      const response = await fetch(target, { method: 'GET' });
      const body = await response.text();

      let statusNote = '';
      if (response.status === 200) {
        statusNote = ' Exposed';
      } else if (response.status === 403) {
        statusNote = ' Forbidden (might exist)';
      } else if (response.status === 404) {
        statusNote = 'Not Found (safe)';
      } else {
        statusNote = `ℹ️ ${response.status} - Unknown`;
      }

      results.push({
        path: file.path,
        url: target,
        status: response.status,
        note: statusNote,
        expectedPublic: file.expectedPublic,
         riskLevel: file.riskLevel,
        contentSnippet: body.slice(0, 100),
      });
    } catch (err) {
      results.push({
        path: file.path,
        url: target,
        status: 'ERROR',
        note: '❌ Request failed',
        expectedPublic: file.expectedPublic,
        riskLevel: file.riskLevel,
      });
    }
  }

  const scan = await SensitiveFileScan.create({ url, results, scannedAt: new Date() });

  res.json({
    url,
    results,
    scannedAt: scan.scannedAt,
    _id: scan._id,
    message: 'Scan complete and saved',
  });
};
