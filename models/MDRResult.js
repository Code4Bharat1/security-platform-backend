// models/MDRResult.js
import mongoose from "mongoose";

const mdrResultSchema = new mongoose.Schema({
  url: String,
  threatDetected: Boolean,
  message: String,
  timestamp: {
    type: Date,
    default: Date.now,
  },
});

export const MDRResult = mongoose.model("MDRResult", mdrResultSchema);

// Function to save result
export const saveMDRResult = async ({ url, threatDetected, message }) => {
  const entry = new MDRResult({ url, threatDetected, message });
  await entry.save();
};
