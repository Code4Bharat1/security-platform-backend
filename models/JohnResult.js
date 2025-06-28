// models/JohnResult.js
import mongoose from "mongoose";

const johnResultSchema = new mongoose.Schema({
  hash: String,
  result: String,
  timestamp: { type: Date, default: Date.now },
});

const JohnResult = mongoose.model("JohnResult", johnResultSchema);

export const saveJohnResult = async (data) => {
  const entry = new JohnResult(data);
  await entry.save();
};

export default JohnResult;
