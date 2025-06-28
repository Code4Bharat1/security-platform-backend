// controllers/whatsappPrivacyController.js
import WhatsAppPrivacyResult from "../models/WhatsAppPrivacyResult.js";

export const inspectPrivacy = async (req, res) => {
  const { settings } = req.body;

  if (!settings) {
    return res.status(400).json({ message: "Settings not provided" });
  }

  const risks = [];

  if (settings.profilePhoto === "Everyone") risks.push("Profile photo visible to everyone.");
  if (settings.lastSeen === "Everyone") risks.push("Last seen visible to everyone.");
  if (settings.groups === "Everyone") risks.push("Anyone can add you to groups.");
  if (settings.readReceipts === true) risks.push("Read receipts are enabled.");

  const result = new WhatsAppPrivacyResult({
    settings,
    risks,
  });

  await result.save();

  res.json({
    message: "✅ Privacy settings inspected.",
    risks,
    totalRisks: risks.length,
  });
};
