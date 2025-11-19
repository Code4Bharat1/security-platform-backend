import express from 'express';
import { runScan, getHistory } from '../controllers/scanController.js';
import { authMiddleware } from '../middleware/authMiddleware.js';
import { checkCredits } from '../middleware/checkCredits.js';

const router = express.Router();

// POST /api/scan/run-scan
router.post('/run-scan', runScan);

// GET /api/scan/history
router.get('/history', authMiddleware, getHistory);


export default router;
