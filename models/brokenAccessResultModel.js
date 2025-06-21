import mongoose from 'mongoose';

const brokenAccessResultSchema = new mongoose.Schema({
  targetUrl: {
    type: String,
    required: true,
  },
  results: [
    {
      test: String,
      statusCode: mongoose.Schema.Types.Mixed,
      containsSensitiveInfo: Boolean,
      result: String,
      reason: String,
    },
  ],
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

export const BrokenAccessResult = mongoose.models.BrokenAccessResult || mongoose.model('BrokenAccessResult', brokenAccessResultSchema);

