import mongoose from "mongoose";

const osintResultSchema = new mongoose.Schema({
  queryType: String,       // username / email / phone
  queryValue: String,
  foundOn: [String],       // list of sites
  checkedAt: { type: Date, default: Date.now }
});

export default mongoose.model("OsintResult", osintResultSchema);
