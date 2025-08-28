import mongoose from "mongoose";

const PasswordMetricSchema = new mongoose.Schema(
  {
    length: { type: Number, required: true },
    classes: {
      lower: { type: Boolean, required: true },
      upper: { type: Boolean, required: true },
      number: { type: Boolean, required: true },
      symbol: { type: Boolean, required: true },
    },
    entropyBits: { type: Number, required: true },
    crackTimeSeconds: { type: Number, required: true },
    score: { type: Number, required: true },  // 0..100
    label: { type: String, required: true },  // Weak/Medium/Strong/Very Strong
    advice: [{ type: String }],
    ip: { type: String },                      // optional
    ua: { type: String },                      // optional user-agent
  },
  { timestamps: true }
);

// Reuse model in dev if already compiled
export default mongoose.models.PasswordMetric
  || mongoose.model("PasswordMetric", PasswordMetricSchema);
