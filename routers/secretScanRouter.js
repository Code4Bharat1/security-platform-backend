import express from 'express';
import { scanSecretKeys } from '../controllers/secretScanController.js';

const router = express.Router();

// POST /api/secretKeyScanner/scan
router.post('/secret-scan', scanSecretKeys);

export default router;
