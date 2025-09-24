import mongoose from 'mongoose';

const userSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },

    // 👇 NEW FIELD: credits system
    credits: {
      type: Number,
      default: 10,   // every new user starts with 10 credits
      min: 0,        // no negative balances
    },
  },
  { timestamps: true }
); 

const User = mongoose.models.User || mongoose.model('User', userSchema);

export default User;
