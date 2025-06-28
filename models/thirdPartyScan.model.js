// models/thirdPartyScan.model.js
import mongoose from "mongoose";

const thirdPartyScanSchema = new mongoose.Schema(
  {
    appName: { type: String, required: true },
    permissions: [String],
    risky: [String],
    resultMessage: { type: String },
  },
  { timestamps: true }
);

const ThirdPartyScan = mongoose.model("ThirdPartyScan", thirdPartyScanSchema);
export default ThirdPartyScan;
