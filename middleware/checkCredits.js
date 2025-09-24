// middleware/checkCredits.js
import User from "../models/user.js";

export const checkCredits = (cost = 1) => {
  return async (req, res, next) => {
    try {
      const user = req.user; // already set by authMiddleware
      if (user.credits < cost) {
        return res.status(403).json({ message: "Not enough credits. Please recharge!" });
      }

      // Deduct credits
      user.credits -= cost;
      await user.save();

      next();
    } catch (error) {
      console.error("Credit check error:", error);
      res.status(500).json({ message: "Error checking credits" });
    }
  };
};
