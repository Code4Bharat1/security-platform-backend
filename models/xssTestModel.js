// models/xssTestModel.js
import mongoose from 'mongoose';

const xssTestSchema = new mongoose.Schema({
  url: { type: String, required: true },
  param: { type: String, required: true },
  payload: { type: String, required: true },
  result: { type: mongoose.Schema.Types.Mixed }, // flexible to store any result structure
  testedAt: { type: Date, default: Date.now },
});

export const XssTest = mongoose.model('XssTest', xssTestSchema);
