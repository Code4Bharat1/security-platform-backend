import SocialPrivacyResult from "../models/socialPrivacyResult.js";

export const analyzeProfile = async (req, res) => {
  try {
    const { url } = req.body;
    console.log("📩 URL received:", url); // ✅ DEBUG

    if (!url) {
      return res.status(400).json({ message: "Profile URL is required" });
    }

    const risks = [];

    // Dummy logic
    if (url.includes("instagram")) risks.push("Bio may contain personal info");
    if (url.includes("linkedin")) risks.push("Public career data visible");
    if (url.includes("facebook")) risks.push("Public friend list detected");
    if (url.match(/@[a-zA-Z0-9._]+/)) risks.push("Username exposed");

    if (risks.length === 0) risks.push("No major privacy risks detected");

    const result = new SocialPrivacyResult({
      profileUrl: url,
      risks,
    });

    await result.save();

    res.status(200).json({
      message: "Privacy analysis complete.",
      risks,
    });
  } catch (err) {
    console.error("❌ Error in analyzer:", err);
    res.status(500).json({ message: "Internal Server Error", error: err.message });
  }
};
