// models/scanResultModel.js
import mongoose from 'mongoose';

const vulnerabilitySchema = new mongoose.Schema({
  type: String,
  severity: String,
  description: String,
  details: String,
  recommendation: String
}, { _id: false });

const scanResultSchema = new mongoose.Schema({
  domain: { type: String, index: true },
  timestamp: { type: Date, index: true },
  ssl: mongoose.Schema.Types.Mixed,
  headers: {
    type: Object,
    default: {},
    // ✅ This ensures proper serialization
  },
  openPorts: mongoose.Schema.Types.Mixed,
  vulnerabilities: [vulnerabilitySchema],
  vulnerabilityCount: Number,
  riskLevel: String,
  timespan: { type: Number, default: 0 },
  sitemap: mongoose.Schema.Types.Mixed,
  robots: mongoose.Schema.Types.Mixed,
  htmlAnalysis: mongoose.Schema.Types.Mixed
}, {
  strict: false,  // ✅ Allow flexible nested fields
  minimize: false // ✅ Keep empty objects/arrays
});

scanResultSchema.pre('save', function (next) {
  // Convert headers object to plain object if it exists
  if (this.headers && typeof this.headers === 'object') {
    this.headers = JSON.parse(JSON.stringify(this.headers));
  }
  next();
});

export default mongoose.models.ScanResult || mongoose.model('ScanResult', scanResultSchema);
