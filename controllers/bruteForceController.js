// controllers/bruteForceController.js
import fetch from 'node-fetch';
import { BruteForceResult } from '../models/bruteForceModel.js';

const wordlist = [
  "/admin", "/login", "/dashboard", "/config", "/.git", "/.env", "/uploads",
  "/images", "/css", "/js", "/api", "/backup", "/db", "/test", "/old", "/dev",
  "/private", "/cgi-bin", "/scripts", "/phpmyadmin", "/webadmin", "/wp-admin",
  "/wp-login", "/cpanel", "/user", "/users", "/static", "/assets", "/logs",
  "/temp", "/tmp", "/bin"
];

export const bruteForceScan = async (req, res) => {
  try {
    let { target } = req.body;
    if (!target || !target.startsWith('http')) {
      return res.status(400).json({ error: 'Invalid target URL' });
    }
    // Ensure no trailing slash
    if (target.endsWith('/')) target = target.slice(0, -1);

    const results = [];

    for (const path of wordlist) {
      const fullUrl = `${target}${path}`;
      try {
        const response = await fetch(fullUrl, { method: 'GET', redirect: 'manual' });
        const status = response.status;
        let statusResult = "❌ Not Found";

        if (status === 200) statusResult = "✅ Accessible";
        else if (status === 403 || (status >= 300 && status < 400)) {
          statusResult = `⚠️ Possible - Status ${status}`;
        }

        results.push({ path, status, result: statusResult });
      } catch (err) {
        results.push({ path, status: "Error", result: "⚠️ Request Failed" });
      }
    }

    // Optional: save to DB
    await BruteForceResult.create({ target, results });

    res.json({ results });
  } catch (error) {
    console.error('Scan failed:', error);
    res.status(500).json({ error: 'Directory brute force scan failed' });
  }
};
