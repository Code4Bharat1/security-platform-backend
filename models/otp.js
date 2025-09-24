import mongoose from 'mongoose';

const otpSchema = new mongoose.Schema({
  email: { type: String, required: true },
  code: { type: String, required: true },
  expires: { type: Date, required: true },
  verified: { type: Boolean, default: false }
});

export const Otp = mongoose.model('Otp', otpSchema);

// export default Otp;