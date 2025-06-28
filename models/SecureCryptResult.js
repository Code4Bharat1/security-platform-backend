import mongoose from "mongoose";

const secureCryptSchema = new mongoose.Schema({
  type: String, // 'encrypt' or 'decrypt'
  input: String,
  output: String,
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const SecureCryptResult = mongoose.model("SecureCryptResult", secureCryptSchema);

export const saveSecureCryptResult = async (data) => {
  const entry = new SecureCryptResult(data);
  await entry.save();
};

export default SecureCryptResult;
