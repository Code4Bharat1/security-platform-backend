import express from 'express';
import { analyzeFingerprint } from '../controllers/fingerprintController.js';

const router = express.Router();

router.post('/fingerprint-scan', analyzeFingerprint);

export default router;
