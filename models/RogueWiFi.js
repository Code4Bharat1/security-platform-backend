import mongoose from "mongoose";

const rogueWiFiSchema = new mongoose.Schema({
  input: String,
  status: String,
  message: String,
  timestamp: {
    type: Date,
    default: Date.now,
  },
});

export default mongoose.model("RogueWiFi", rogueWiFiSchema);
