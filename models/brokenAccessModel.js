// models/brokenAccessModel.js
import mongoose from 'mongoose';

const resultSchema = new mongoose.Schema({
  test: String,
  statusCode: Number,
  containsSensitiveInfo: Boolean,
  result: String,
  reason: String,
});

const brokenAccessScanSchema = new mongoose.Schema({
  targetUrl: String,
  customPaths: [String],
  authHeaderUsed: { type: Boolean, default: false },
  results: [resultSchema],
  createdAt: { type: Date, default: Date.now },
});

export const BrokenAccessScan = mongoose.model('BrokenAccessScan', brokenAccessScanSchema);
