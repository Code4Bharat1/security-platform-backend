import mongoose from 'mongoose';


// ===== Broken Link Scan Schema =====
const linkSchema = new mongoose.Schema({
  url: String,
  status: String,
  ok: Boolean,
});

const brokenLinkScanSchema = new mongoose.Schema({
  scannedUrl: { type: String, required: true },
  scannedAt: { type: Date, default: Date.now },
  links: [linkSchema],
});

export const BrokenLinkScan = mongoose.model('BrokenLinkScan', brokenLinkScanSchema);
