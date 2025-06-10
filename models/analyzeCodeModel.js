// models/analyzeCodeModel.js
import mongoose from 'mongoose';

const resultSchema = new mongoose.Schema({
  message: { type: String, required: true },
  passed: { type: Number, required: true },
  failed: { type: Number, required: true },
  results: { type: [String], default: [] },
}, { _id: false });

const analyzeCodeSchema = new mongoose.Schema({
  code: { type: String, required: true },
  results: { type: resultSchema, required: true },
  lines: { type: Number, required: true },
  fileLength: { type: Number, required: true },
  createdAt: { type: Date, default: Date.now },
});

// 👇 Optional: explicitly define the collection name
export const CodeAnalysis = mongoose.model('CodeAnalysis', analyzeCodeSchema, 'codeanalyses');
