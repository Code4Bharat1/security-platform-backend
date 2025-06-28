import axios from "axios";
import SQLiResult from "../models/sqliResult.js";

export const scanSQLi = async (req, res) => {
  const { url } = req.body;

  try {
    const testUrl = url.includes("?") ? url + "'" : url + "/'";

    const response = await axios.get(testUrl);

    const isVulnerable = /sql syntax|mysql_fetch|you have an error in your sql/i.test(response.data);


    const result = new SQLiResult({
      url,
      vulnerable: isVulnerable,
      message: isVulnerable
        ? "❌ Website might be vulnerable to SQL Injection!"
        : "✅ Website seems safe from basic SQLi.",
    });

    await result.save();

    res.json({
      url,
      vulnerable: isVulnerable,
      message: result.message,
      scannedAt: result.scannedAt,
    });
  } catch (error) {
    const isVulnerable = /sql|syntax|mysql|error/i.test(
      error?.response?.data || ""
    );

    const result = new SQLiResult({
      url,
      vulnerable: isVulnerable,
      message: isVulnerable
        ? "❌ Website might be vulnerable to SQL Injection!"
        : "✅ Website seems safe from basic SQLi.",
    });

    await result.save();

    res.json({
      url,
      vulnerable: isVulnerable,
      message: result.message,
      scannedAt: result.scannedAt,
    });
  }
};
