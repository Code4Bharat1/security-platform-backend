import express from 'express';
import { runScan, getHistory } from '../controllers/scanController.js';

const router = express.Router();

// POST /api/scan/run-scan
router.post('/run-scan', runScan);

// GET /api/scan/history
router.get('/history', getHistory);

export default router;
