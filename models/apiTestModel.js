// backend/models/apiTestModel.js
import mongoose from "mongoose";

const apiTestModelSchema = new mongoose.Schema({
  url: { type: String, required: true },
  method: { type: String, required: true },
  headers: { type: Object, default: {} },
  body: { type: Object, default: {} },
  status: { type: Number, required: true },
  statusText: { type: String },
  responseTime: { type: Number },
  responseHeaders: { type: Object, default: {} },
  responseData: { type: Object },
  securityChecks: {
    authentication: {
      status: String,
      secure: String,
    },
    headerSecurity: {
      type: Map,
      of: {
        status: String,
        recommendation: String,
      },
    },
    ssl: {
      status: String,
      hstsStatus: String,
      recommendation: String,
    },
    sensitiveDataExposure: {
      status: String,
      details: mongoose.Mixed,
    },
    injectionVulnerability: {
      status: String,
      details: mongoose.Mixed,
    },
  },
  securityScorecard: {
    score: Number,
    rating: String,
  },
  recommendations: [{ type: String }],
  timestamp: { type: Date, default: Date.now },
});

export default mongoose.model("ApiTestModel", apiTestModelSchema);