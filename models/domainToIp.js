import mongoose from 'mongoose';

const domainSchema = new mongoose.Schema({
  domain: { type: String, required: true },
  type: { type: String, default: 'A' },
  result: { type: Object },
  timestamp: { type: Date, default: Date.now }
});

export default mongoose.model('domainLog', domainSchema);
