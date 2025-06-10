import mongoose from 'mongoose';

const resultSchema = new mongoose.Schema({
  subdomain: String,
});
       
const subdomainSchema = new mongoose.Schema({
  domain: { type: String, required: true },
  results: [resultSchema],
  timestamp: { type: Date, default: Date.now },
});

export const SubdomainResult = mongoose.model('SubdomainResult', subdomainSchema);
