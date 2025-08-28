import mongoose from 'mongoose';

const seoResultSchema = new mongoose.Schema({
  url: { type: String, required: true, unique: true },
  score: { type: Number, required: true },
  issues: { type: [String], default: [] },
  strengths: { type: [String], default: [] },
  pageSizeKB: { type: Number },
  mobileFriendly: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

export default mongoose.model('SeoResult', seoResultSchema);
