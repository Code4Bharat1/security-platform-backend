// usbScanController.js
import multer from "multer";
import crypto from "crypto";

// Multer in-memory storage
const storage = multer.memoryStorage();
const upload = multer({ storage }).single("file");

// Suspicious patterns and known malware hashes
const suspiciousPatterns = [
  ".exe", ".bat", ".scr", ".cmd", ".pif", ".com", ".vbs", ".js", ".jar",
  "autorun.inf", "malware", "virus", "trojan", "worm", "ransom", "spyware"
];

const knownMalwareHashes = new Set([
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
]);

// Generate SHA-256 hash
function generateHash(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

// Controller function
export const scanUSB = (req, res) => {
  upload(req, res, (err) => {
    if (err || !req.file) {
      return res.status(400).json({ message: "File upload failed or missing file." });
    }

    const file = req.file;
    const fileName = file.originalname.toLowerCase();
    const fileBuffer = file.buffer;

    const matchedPatterns = suspiciousPatterns.filter(pattern =>
      fileName.includes(pattern)
    );

    const fileHash = generateHash(fileBuffer);
    const malwareDetected = knownMalwareHashes.has(fileHash);

    const suspiciousFiles = (matchedPatterns.length > 0 || malwareDetected) ? [{
      file: file.originalname,
      matchedPatterns,
      fileHash,
      malwareDetected
    }] : [];

    res.status(200).json({
      message: "Scan complete",
      totalFilesScanned: 1,
      suspiciousCount: suspiciousFiles.length,
      suspiciousFiles
    });
  });
};
