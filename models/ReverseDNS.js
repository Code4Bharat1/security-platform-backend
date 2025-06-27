import mongoose from 'mongoose';

const ReverseDNSchema = new mongoose.Schema({
  ip: { type: String, required: true, unique: true },
  domains: [String], // PTR records/domains found
  lookedUpAt: { type: Date, default: Date.now },

  // New timespan field (milliseconds)
  timespan: { type: Number, default: 0 },
});

const ReverseDNS = mongoose.models.ReverseDNS || mongoose.model('ReverseDNS', ReverseDNSchema);

export default ReverseDNS;
           
