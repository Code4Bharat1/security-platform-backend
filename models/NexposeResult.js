// models/NexposeResult.js
import mongoose from 'mongoose';

const nexposeResultSchema = new mongoose.Schema({
  url: String,
  vulnerable: Boolean,
  details: String,
  timestamp: {
    type: Date,
    default: Date.now,
  },
});

export const NexposeResult = mongoose.model('NexposeResult', nexposeResultSchema);

export const saveNexposeResult = async (data) => {
  const result = new NexposeResult(data);
  await result.save();
};
