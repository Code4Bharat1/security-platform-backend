// models/bruteForceModel.js
import mongoose from 'mongoose';

const resultSchema = new mongoose.Schema({
  path: String,
  status: String,
  result: String,
});

const bruteForceSchema = new mongoose.Schema({
  target: String,
  results: [resultSchema],
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

export const BruteForceResult = mongoose.model('BruteForceResult', bruteForceSchema);
