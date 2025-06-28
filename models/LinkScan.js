import mongoose from "mongoose";

const linkScanSchema = new mongoose.Schema({
  url: String,
  status: String,
  message: String,
  scannedAt: {
    type: Date,
    default: Date.now,
  },
});

export default mongoose.model("LinkScan", linkScanSchema);
