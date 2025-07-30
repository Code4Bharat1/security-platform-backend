import OsintResult from '../models/OsintResult.js';

const knownSites = [
  "Facebook", "Twitter", "Instagram", "LinkedIn", "GitHub", "Reddit", 
  "Pinterest", "Tumblr", "Snapchat", "TikTok"
];

export const checkOsint = async (req, res) => {
  try {
    const { username, email, phone } = req.body;

    let foundOn = [];
    let queryType = "";
    let queryValue = "";

    if (username) {
      queryType = "username";
      queryValue = username;

      // Dummy: randomly pick 3 sites if length > 3
      if (username.length > 3) {
        foundOn = knownSites.sort(() => 0.5 - Math.random()).slice(0, 3);
      }
    }
    else if (email) {
      queryType = "email";
      queryValue = email;

      // Dummy: if email has '@', pick 2-4 sites
      if (email.includes("@")) {
        const count = Math.floor(Math.random() * 3) + 2; // 2-4
        foundOn = knownSites.sort(() => 0.5 - Math.random()).slice(0, count);
      }
    }
    else if (phone) {
      queryType = "phone";
      queryValue = phone;

      // Dummy: if phone length >= 8, pick 1-3 sites
      if (phone.length >= 8) {
        const count = Math.floor(Math.random() * 3) + 1; // 1-3
        foundOn = knownSites.sort(() => 0.5 - Math.random()).slice(0, count);
      }
    } else {
      return res.status(400).json({ message: "Please provide username, email, or phone number to scan." });
    }

    // Save to DB
    const result = new OsintResult({ queryType, queryValue, foundOn });
    await result.save();

    res.json({
      success: true,
      queryType,
      queryValue,
      foundOn,
      checkedAt: result.checkedAt
    });
  } catch (err) {
    console.error("OSINT error:", err);
    res.status(500).json({ success: false, message: "Server error during OSINT scan" });
  }
};
