// middleware/sseAuthMiddleware.js
import jwt from 'jsonwebtoken';
import User from '../models/user.js';

/**
 * SSE-specific auth middleware
 * Accepts token from query parameter (EventSource doesn't support headers)
 */
export const sseAuthMiddleware = async (req, res, next) => {
    try {
        const token = req.query.token;

        console.log("🔐 SSE Auth - Token:", token ? "Present" : "Missing");

        if (!token) {
            return res.status(401).json({
                message: 'Unauthorized: No token in query parameter'
            });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.id).select('_id email credits');

        if (!user) {
            return res.status(401).json({ message: 'Unauthorized: User not found' });
        }

        req.user = user;
        console.log("✅ SSE Auth - User:", user.email, "Credits:", user.credits);
        next();
    } catch (err) {
        console.error("❌ SSE Auth error:", err.message);
        return res.status(401).json({ message: `Unauthorized: ${err.message}` });
    }
};

export default sseAuthMiddleware;
