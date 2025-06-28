import mongoose from "mongoose";

const dataLeakResultSchema = new mongoose.Schema({
  filename: String,
  totalLinesScanned: Number,
  sensitiveMatches: [String],
  detectedAt: {
    type: Date,
    default: Date.now,
  },
});

export default mongoose.model("DataLeakResult", dataLeakResultSchema);
