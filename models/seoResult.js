import mongoose from 'mongoose';

const seoResultSchema = new mongoose.Schema({
  url: { type: String, required: true },
  score: { type: Number, required: true },
  issues: [{ type: String }],
}, { timestamps: true });

export default mongoose.model('SeoResult', seoResultSchema);
