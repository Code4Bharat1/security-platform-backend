import mongoose from "mongoose";

const fakeSoftwareSchema = new mongoose.Schema({
  fileName: String,
  detected: Boolean,
  scannedAt: {
    type: Date,
    default: Date.now,
  },
});

export default mongoose.model("FakeSoftwareResult", fakeSoftwareSchema);
