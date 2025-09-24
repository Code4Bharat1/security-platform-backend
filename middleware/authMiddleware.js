import jwt from 'jsonwebtoken';
import User from '../models/user.js';

export const authMiddleware = async (req, res, next) => {
  try {
    const token =
      req.cookies?.access_token ||
      (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.split(' ')[1] : null);

    console.log("Token received:", token ? "Present" : "Missing");
    if (!token) {
      return res.status(401).json({ message: 'Unauthorized: No token provided' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log("Decoded token:", decoded);
    const user = await User.findById(decoded.id).select('_id email credits');
    if (!user) {
      console.log("User not found for ID:", decoded.id);
      return res.status(401).json({ message: 'Unauthorized: User not found' });
    }

    req.user = user;
    console.log("User authenticated:", user.email, "Credits:", user.credits);
    next();
  } catch (err) {
    console.error("Auth middleware error:", err.message);
    return res.status(401).json({ message: `Unauthorized: ${err.message}` });
  }
};