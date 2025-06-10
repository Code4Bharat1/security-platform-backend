import mongoose from 'mongoose';

const fingerprintSchema = new mongoose.Schema({
  url: String,
  technologies: [String],
  timestamp: {
    type: Date,
    default: Date.now,
  },
});

export const FingerprintResult = mongoose.model('FingerprintResult', fingerprintSchema);
