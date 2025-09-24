// import express from 'express';
// import { signup, login, logout, inspectToken } from '../controllers/auth.controller.js';
// import { authMiddleware } from '../middleware/authMiddleware.js';
// import { checkCredits } from '../middleware/checkCredits.js';

// const router = express.Router();

// // Public routes (no auth required)
// router.post('/signup', signup);
// router.post('/login', login);
// router.post('/logout', logout);

// // Protected route (requires authentication and credits)
// router.post('/inspect-token', authMiddleware, checkCredits(1), inspectToken);

// export default router;