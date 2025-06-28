// models/EmailAttachmentResult.js
import mongoose from "mongoose";

const emailAttachmentResultSchema = new mongoose.Schema({
  filename: String,
  result: String,
  scannedAt: { type: Date, default: Date.now },
});

const EmailAttachmentResult = mongoose.model("EmailAttachmentResult", emailAttachmentResultSchema);

export const saveEmailScanResult = async ({ filename, result }) => {
  const entry = new EmailAttachmentResult({ filename, result });
  await entry.save();
};

export default EmailAttachmentResult;
