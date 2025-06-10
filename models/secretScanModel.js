import mongoose from 'mongoose';

const secretScanSchema = new mongoose.Schema({
  code: { type: String, required: true },
  results: [
    {
      type: { type: String },
      line: { type: Number },
      secret: { type: String },
      severity: { type: String },
      suggestion: { type: String },
    },
  ],
  scannedAt: { type: Date, default: Date.now },
});

export const SecretScan = mongoose.model('SecretScan', secretScanSchema);
