import UsbScanResult from "../models/usbScanResult.js";

const suspiciousPatterns = [".exe", ".bat", ".scr", "autorun.inf", "malware", "virus"];

export const scanUSB = async (req, res) => {
  try {
    const { deviceName, files } = req.body;

    if (!deviceName || !Array.isArray(files)) {
      return res.status(400).json({ message: "Invalid input" });
    }

    const suspiciousFiles = files.filter(file =>
      suspiciousPatterns.some(pattern => file.toLowerCase().includes(pattern))
    );

    const result = new UsbScanResult({
      deviceName,
      totalFilesScanned: files.length,
      suspiciousFiles,
    });

    await result.save();

    res.status(200).json({
      message: "USB Scan Complete",
      totalFilesScanned: files.length,
      suspiciousFiles,
    });
  } catch (error) {
    res.status(500).json({ message: "Scan failed", error: error.message });
  }
};
