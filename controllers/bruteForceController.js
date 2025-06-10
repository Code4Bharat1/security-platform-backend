// controllers/bruteForceController.js
import { BruteForceResult } from '../models/bruteForceModel.js';
import fetch from 'node-fetch';

const wordlist = [
  "/admin", "/admin/", "/admin/login", "/admin.php",
  "/login", "/login.php", "/dashboard", "/dashboard.php",
  "/config", "/config.php", "/.git", "/.env", "/.htaccess",
  "/uploads", "/uploads/", "/images", "/images/",
  "/css", "/js", "/api", "/server-status", "/backup", "/db",
  "/test", "/test/", "/old", "/old_site", "/dev", "/private",
  "/cgi-bin", "/cgi-bin/", "/scripts", "/scripts/", "/phpmyadmin",
  "/webadmin", "/wp-admin", "/wp-login", "/cpanel", "/user", "/users",
  "/static", "/assets", "/logs", "/log", "/temp", "/tmp", "/bin"
];

export const bruteForceScan = async (req, res) => {
  try {
    const { target } = req.body;

    if (!target || !target.startsWith('http')) {
      return res.status(400).json({ error: 'Invalid target URL' });
    }

    const results = [];

    for (const path of wordlist) {
      const fullUrl = `${target}${path}`;
      try {
        const response = await fetch(fullUrl, { method: 'GET', redirect: 'manual' });
        const status = response.status;

        let statusResult = "❌ Not Found";
        if (status === 200) {
          statusResult = "✅ Accessible";
        } else if (status === 403 || (status >= 300 && status < 400)) {
          statusResult = `⚠️ Possible - Status ${status}`;
        }

        results.push({ path, status, result: statusResult });
      } catch (err) {
        results.push({ path, status: "Error", result: "⚠️ Request Failed" });
      }
    }

    const record = new BruteForceResult({ target, results });
    await record.save();

    res.json({ results });
  } catch (error) {
    console.error('Scan failed:', error);
    res.status(500).json({ error: 'Directory brute force scan failed' });
  }
};
