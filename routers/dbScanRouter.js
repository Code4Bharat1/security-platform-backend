import express from 'express';
import { scanDatabase } from '../controllers/dbScanController.js';

const router = express.Router();

router.post('/scan', scanDatabase);

export default router;
