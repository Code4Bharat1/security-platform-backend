import mongoose from 'mongoose';

const qrResultSchema = new mongoose.Schema({
  data: { type: String, required: true },
  status: { type: String, enum: ['safe', 'fake'], required: true },
  reason: { type: String, required: true },
  scannedAt: { type: Date, default: Date.now }
});

export const QrResult = mongoose.model('QrResult', qrResultSchema);
