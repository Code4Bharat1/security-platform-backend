// models/FolderScanResult.js
import mongoose from "mongoose";

const folderScanSchema = new mongoose.Schema({
  filesScanned: Number,
  suspiciousFiles: Number,
  detectedFiles: [String],
  timestamp: { type: Date, default: Date.now },
});

const FolderScanResult = mongoose.model("FolderScanResult", folderScanSchema);
export default FolderScanResult;
