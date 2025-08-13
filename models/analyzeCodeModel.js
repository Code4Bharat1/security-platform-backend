// models/analyzeCodeModel.js
import mongoose from "mongoose";

const issueSchema = new mongoose.Schema(
  {
    line: Number,
    type: String,     // e.g., 'xss', 'sqli'
    message: String,
  },
  { _id: false }
);

const resultSchema = new mongoose.Schema(
  {
    message: String,
    passed: Number,
    failed: Number,
    issues: [issueSchema],
  },
  { _id: false }
);

const analysisSchema = new mongoose.Schema(
  {
    code: { type: String, required: true },
    results: resultSchema,
    lines: Number,
    fileLength: Number,
  },
  { timestamps: true, versionKey: false }
);

analysisSchema.index({ createdAt: -1 });

export const CodeAnalysis =
  mongoose.models.CodeAnalysis ||
  mongoose.model("CodeAnalysis", analysisSchema);
