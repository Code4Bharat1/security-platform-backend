// models/sonarModel.js
import mongoose from 'mongoose';

const issueSchema = new mongoose.Schema({
  line: Number,
  message: String,
});

const sonarSchema = new mongoose.Schema({
  code: { type: String, required: true },
  issues: [issueSchema],
  analyzedAt: { type: Date, default: Date.now },
});

export const SonarResult = mongoose.model('SonarResult', sonarSchema);
