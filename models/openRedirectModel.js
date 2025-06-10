import mongoose from 'mongoose';

const openRedirectSchema = new mongoose.Schema({
  originalUrl: { type: String, required: true },
  testedUrl: { type: String, required: true },
  finalUrl: { type: String, required: true },
  originalDomain: { type: String },
  finalDomain: { type: String },
  vulnerable: { type: Boolean },
  testedAt: { type: Date, default: Date.now },
});

export const OpenRedirect = mongoose.model('OpenRedirect', openRedirectSchema);
