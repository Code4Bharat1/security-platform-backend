import mongoose from 'mongoose';

const registrarSchema = new mongoose.Schema({
  name: String,
  url: String,
});

const ownerSchema = new mongoose.Schema({
  organization: String,
  country: String,
});

const whoisSchema = new mongoose.Schema({
  name: String,
  status: String,
  created: String,
  expires: String,
  registrar: registrarSchema,
  contacts: {
    owner: [ownerSchema],
  },
  nameservers: [String],
  domain: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
});

export const Whois = mongoose.model('Whois', whoisSchema);
