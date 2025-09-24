import express from 'express';
import { signup, login, logout, inspectToken, rechargeCredits } from '../controllers/authController.js';
import { authMiddleware } from '../middleware/authMiddleware.js';
import { checkCredits } from '../middleware/checkCredits.js';

const router = express.Router();

// Public routes (no auth required)
router.post('/signup', signup);
router.post('/login', login);
router.post('/logout', logout);

// Protected routes (require authentication)
router.post('/inspect-token', authMiddleware, checkCredits(1), inspectToken);
router.post('/recharge-credits', authMiddleware, rechargeCredits);

export default router;