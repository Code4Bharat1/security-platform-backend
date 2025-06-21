import mongoose from 'mongoose';

const resultSchema = new mongoose.Schema({
  url: String,
  scannedAt: { type: Date, default: Date.now },
  results: [
    {
      path: String,
      url: String,
      status: String,
      note: String,
      contentSnippet: String,
    },
  ],
});

export const SensitiveFileScan = mongoose.model('SensitiveFileScan', resultSchema);
