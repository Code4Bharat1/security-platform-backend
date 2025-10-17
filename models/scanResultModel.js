// models/scanResultModel.js
import mongoose from 'mongoose';

const vulnerabilitySchema = new mongoose.Schema({
  type: String,
  severity: String,
  description: String,
  details: String,
  recommendation: String
}, { _id: false });

// Keep headers flexible, but allow nested objects like cookies/csp/_benchmark
// Mixed is fine for your use-case.
const scanResultSchema = new mongoose.Schema({
  domain: { type: String, index: true },
  timestamp: { type: Date, index: true },    // ← better as Date for sorting
  ssl: mongoose.Schema.Types.Mixed,
  headers: mongoose.Schema.Types.Mixed,
  openPorts: mongoose.Schema.Types.Mixed,
  vulnerabilities: [vulnerabilitySchema],
  vulnerabilityCount: Number,
  riskLevel: String,
  timespan: { type: Number, default: 0 },

  // NEW: persist your added features
  sitemap: mongoose.Schema.Types.Mixed,       // { present, url, summary: { ... } }
  robots: mongoose.Schema.Types.Mixed,        // { present, allowsAll, disallowCount }
  htmlAnalysis: mongoose.Schema.Types.Mixed   // { formsFound, passwordFields, ... }
}, {
  strict: true
});

export default mongoose.models.ScanResult || mongoose.model('ScanResult', scanResultSchema);
