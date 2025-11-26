import express from 'express';
import { signup, login, logout, inspectToken, rechargeCredits, verifyToken } from '../controllers/authController.js';
import { authMiddleware } from '../middleware/authMiddleware.js';
import { checkCredits } from '../middleware/checkCredits.js';
import { testToken } from "../controllers/tokenInspector.js"

const router = express.Router();

// Public routes (no auth required)
router.post('/signup', signup);
router.post('/login', login);
router.post('/logout', logout);

// Protected routes (require authentication)
router.get('/verify-token', authMiddleware, verifyToken);
router.post('/inspect-token', authMiddleware, checkCredits(1), inspectToken);
router.post('/recharge-credits', authMiddleware, rechargeCredits);
router.post("/oauthTokenInspector", authMiddleware, checkCredits(1), testToken)


export default router;