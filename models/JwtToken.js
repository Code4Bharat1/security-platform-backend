import mongoose from "mongoose";

const jwtTokenSchema = new mongoose.Schema({
  token: { type: String, required: true },
  secret: { type: String }, // optional
  createdAt: { type: Date, default: Date.now },
});

// ✅ This line prevents OverwriteModelError
const JwtToken = mongoose.models.JwtToken || mongoose.model("JwtToken", jwtTokenSchema);

export default JwtToken;
