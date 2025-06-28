import mongoose from "mongoose";

const sqliResultSchema = new mongoose.Schema({
  url: String,
  vulnerable: Boolean,
  message: String,
  scannedAt: {
    type: Date,
    default: Date.now,
  },
});

export default mongoose.model("SQLiResult", sqliResultSchema);
