import mongoose from "mongoose";

const hashResultSchema = new mongoose.Schema({
  text: String,
  hash: String,
  algorithm: String,
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

export default mongoose.model("HashResult", hashResultSchema);
