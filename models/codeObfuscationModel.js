// models/codeObfuscationModel.js
import mongoose from 'mongoose';

const CodeObfuscationSchema = new mongoose.Schema({
  code: { type: String, required: true },
  severity: { type: String, enum: ['Low', 'Medium', 'High'], required: true },
  shortVars: [String],
  encodedStringsCount: { type: Number, default: 0 },
  usesEval: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

export const CodeObfuscation = mongoose.model('CodeObfuscation', CodeObfuscationSchema);
