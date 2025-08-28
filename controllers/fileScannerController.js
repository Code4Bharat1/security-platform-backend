// controllers/fileScannerController.js
import crypto from "crypto";
import fs from "fs";
import path from "path";
import fetch from "node-fetch";

// Helper: calculate hash
const calculateHash = (filePath, algorithm) => {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash(algorithm);
    const stream = fs.createReadStream(filePath);
    stream.on("data", (data) => hash.update(data));
    stream.on("end", () => resolve(hash.digest("hex")));
    stream.on("error", (err) => reject(err));
  });
};

// Helper: calculate entropy
const calculateEntropy = (buffer) => {
  const freq = new Array(256).fill(0);
  for (let byte of buffer) freq[byte]++;
  let entropy = 0;
  const total = buffer.length;
  for (let f of freq) {
    if (f > 0) {
      const p = f / total;
      entropy -= p * Math.log2(p);
    }
  }
  return entropy.toFixed(3);
};

// Controller: scan single file
export const scanFile = async (req, res) => {
  const file = req.file;
  if (!file) {
    return res.status(400).json({ error: "No file uploaded." });
  }

  try {
    const filePath = path.resolve(file.path);
    const fileBuffer = fs.readFileSync(filePath);

    // File info
    const fileInfo = {
      name: file.originalname,
      size: file.size,
      type: path.extname(file.originalname).replace(".", "").toUpperCase(),
      path: filePath,
    };

    // Hashes
    const md5 = await calculateHash(filePath, "md5");
    const sha1 = await calculateHash(filePath, "sha1");
    const sha256 = await calculateHash(filePath, "sha256");

    // Entropy
    const entropy = calculateEntropy(fileBuffer);

    // External API (example: VirusTotal, replace with your API key)
    let detectionStatus = "Clean";
    let threatScore = 0;
    let engines = "0/70";
    let malwareFamily = "N/A";

    try {
      const vtResponse = await fetch(`https://www.virustotal.com/api/v3/files/${sha256}`, {
        headers: { "x-apikey": process.env.VIRUSTOTAL_API_KEY }
      });

      if (vtResponse.ok) {
        const vtData = await vtResponse.json();
        const stats = vtData.data.attributes.last_analysis_stats;

        const positives = stats.malicious + stats.suspicious;
        const total = Object.values(stats).reduce((a, b) => a + b, 0);

        engines = `${positives}/${total}`;
        threatScore = Math.min(100, (positives / total) * 100);

        if (positives === 0) detectionStatus = "Clean";
        else if (positives < 5) detectionStatus = "Suspicious";
        else detectionStatus = "Malicious";

        malwareFamily = vtData.data.attributes.popular_threat_classification?.suggested_threat_label || "N/A";
      }
    } catch (err) {
      console.error("⚠️ VirusTotal API error:", err.message);
    }

    // Color coding
    let color = "green";
    if (detectionStatus === "Suspicious") color = "yellow";
    if (detectionStatus === "Malicious") color = "red";

    res.json({
      message: "✅ File scanned successfully",
      file: fileInfo,
      hashes: { md5, sha1, sha256 },
      entropy,
      detection: {
        status: detectionStatus,
        engines,
        malwareFamily,
        threatScore,
        color,
      },
    });

    // Delete file after scan (optional)
    fs.unlinkSync(filePath);

  } catch (error) {
    console.error("File scan error:", error.message);
    res.status(500).json({ error: "Server error while scanning file." });
  }
};
