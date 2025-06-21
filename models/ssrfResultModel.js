// models/ssrfResultModel.js
import mongoose from 'mongoose';

const ssrfResultSchema = new mongoose.Schema({
  targetUrl: { type: String, required: true },
  payloadsTested: [String],
  results: [
    {
      payload: String,
      statusCode: mongoose.Schema.Types.Mixed,
      bodySnippet: String,
      isVulnerable: Boolean
    }
  ],
  createdAt: { type: Date, default: Date.now }
});

export const SSRFResult = mongoose.model('SSRFResult', ssrfResultSchema);