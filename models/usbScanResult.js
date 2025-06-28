import mongoose from "mongoose";

const usbScanResultSchema = new mongoose.Schema({
  deviceName: String,
  totalFilesScanned: Number,
  suspiciousFiles: [String],
  detectedAt: {
    type: Date,
    default: Date.now,
  },
});

export default mongoose.model("UsbScanResult", usbScanResultSchema);
