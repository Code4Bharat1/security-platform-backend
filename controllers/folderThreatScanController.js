// controllers/folderThreatScanController.js
import FolderScanResult from "../models/FolderScanResult.js";

export const scanFolder = async (req, res) => {
  const files = req.files;

  if (!files || files.length === 0) {
    return res.status(400).json({ message: "No files uploaded." });
  }

  const suspiciousFiles = files.filter((file) =>
    file.originalname.toLowerCase().includes("malware")
  );

  const result = new FolderScanResult({
    filesScanned: files.length,
    suspiciousFiles: suspiciousFiles.length,
    detectedFiles: suspiciousFiles.map((f) => f.originalname),
  });

  await result.save();

  res.json({
    message: "✅ Folder scanned successfully.",
    totalFiles: files.length,
    suspiciousFiles: suspiciousFiles.length,
    detected: suspiciousFiles.map((f) => f.originalname),
  });
};
