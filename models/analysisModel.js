// models/analysisModel.js
import mongoose from 'mongoose';

const issueSchema = new mongoose.Schema({
  line: Number,
  snippet: String,
  message: String,
});

const analysisSchema = new mongoose.Schema({
  code: { type: String, required: true },
  issues: [issueSchema],
  analyzedAt: { type: Date, default: Date.now },
});

export const Analysis = mongoose.model('Analysis', analysisSchema);
         