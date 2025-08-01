import fs from "fs";

export const analyzeEmailAttachment = (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: "❌ No file uploaded." });
    }

    const { originalname, size, path } = req.file;

    // Read file content (try utf8, fallback binary)
    let content = "";
    try {
      content = fs.readFileSync(path, "utf8");
    } catch (err) {
      // If not utf8 (e.g., binary), read as buffer and convert to hex or base64 for simple check
      const buffer = fs.readFileSync(path);
      content = buffer.toString("base64");
    }

    // Normalize all to lower case for easy matching
    const loweredContent = content.toLowerCase();
    const loweredName = originalname.toLowerCase();

    // ✅ Common suspicious indicators
    const SUSPICIOUS_KEYWORDS = [
      "wildfire.paloaltonetworks.com",
      "malware",
      "trojan",
      "virus",
      "ransomware",
      "backdoor",
      "powershell",
      "<script",
      ".bat",
      ".vbs",
      "payload",
      "cmd.exe",
      "wget",
      "curl",
      "hacker",
      "exploit",
      "keylogger",
      "phishing",
      "ddos",
      "botnet",
      "shellcode"
    ];

    // ✅ Suspicious file extensions
    const DANGEROUS_EXTENSIONS = [".exe", ".bat", ".vbs", ".ps1", ".sh", ".cmd", ".scr", ".js"];

    // ✅ Size limit: >5MB flagged
    const isLarge = size > 5 * 1024 * 1024;

    // ✅ Check name
    const nameHasSuspicious = SUSPICIOUS_KEYWORDS.some(kw => loweredName.includes(kw));

    // ✅ Check extension
    const hasDangerousExt = DANGEROUS_EXTENSIONS.some(ext => loweredName.endsWith(ext));

    // ✅ Check content
    const contentHasSuspicious = SUSPICIOUS_KEYWORDS.some(kw => loweredContent.includes(kw));

    // ✅ Final decision
    const isSuspicious = nameHasSuspicious || hasDangerousExt || contentHasSuspicious || isLarge;

    const message = isSuspicious
      ? `⚠️ Suspicious attachment detected (${originalname})`
      : `✅ ${originalname} is clean and safe.`;

    res.json({ message });
  } catch (err) {
    console.error("Attachment analyze error:", err);
    res.status(500).json({ message: "❌ Server error analyzing attachment." });
  }
};
