import mongoose from "mongoose";

const socialPrivacySchema = new mongoose.Schema({
  profileUrl: String,
  risks: [String],
  scannedAt: {
    type: Date,
    default: Date.now,
  },
});

export default mongoose.model("SocialPrivacyResult", socialPrivacySchema);
