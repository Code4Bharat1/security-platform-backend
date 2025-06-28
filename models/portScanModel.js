import mongoose from "mongoose";

const portScanSchema = new mongoose.Schema({
  ip: String,
  openPorts: [Number],
  riskyPorts: [Number],
  scannedAt: {
    type: Date,
    default: Date.now,
  },
});

// ✅ Prevent OverwriteModelError
const PortScan = mongoose.models.PortScan || mongoose.model("PortScan", portScanSchema);

export default PortScan;
         
