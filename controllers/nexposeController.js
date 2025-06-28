// controllers/nexposeController.js
import { saveNexposeResult } from "../models/NexposeResult.js";

export const scanForSQLi = async (req, res) => {
  const { url } = req.body;

  // Dummy check (replace with real scanner logic later)
  const isVulnerable = url.includes("'") || url.includes("--");
  const details = isVulnerable
    ? "🚨 SQL Injection vulnerability detected!"
    : "✅ No SQL Injection detected.";

  // Save result to DB
  await saveNexposeResult({ url, vulnerable: isVulnerable, details });

  res.json({ success: true, url, vulnerable: isVulnerable, details });
};
