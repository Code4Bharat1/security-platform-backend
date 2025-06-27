import mongoose from 'mongoose';

const OAuthTokenSchema = new mongoose.Schema({
  token: String,
  payload: Object,
  issues: [String],
  timestamp: { type: Date, default: Date.now }
});

export default mongoose.model('OAuthToken', OAuthTokenSchema);
