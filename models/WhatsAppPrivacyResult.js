// models/WhatsAppPrivacyResult.js
import mongoose from "mongoose";

const privacyResultSchema = new mongoose.Schema({
  settings: Object,
  risks: [String],
  checkedAt: { type: Date, default: Date.now },
});

const WhatsAppPrivacyResult = mongoose.model("WhatsAppPrivacyResult", privacyResultSchema);
export default WhatsAppPrivacyResult;
