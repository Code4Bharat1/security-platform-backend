import FakeSoftwareResult from "../models/fakeSoftwareResult.js";
import multer from "multer";

export const scanFakeSoftware = async (req, res) => {
  try {
    const file = req.file;

    if (!file) {
      return res.status(400).json({ message: "No file uploaded" });
    }

    const fileName = file.originalname.toLowerCase();
    const fakeIndicators = ["crack", "keygen", "patch", "activator", "nulled"];

    const isFake = fakeIndicators.some((keyword) =>
      fileName.includes(keyword)
    );

    // Save result in DB
    await FakeSoftwareResult.create({
      fileName: file.originalname,
      detected: isFake,
    });

    res.status(200).json({
      message: isFake
        ? "⚠️ Fake or malicious software detected."
        : "✅ No fake software detected.",
    });
  } catch (error) {
    console.error("❌ Error during scan:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
};
