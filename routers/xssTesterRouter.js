// routes/xssTesterRoutes.js
import express from 'express';

import { testXssPayload } from '../controllers/xssTesterController.js';
const router = express.Router();

router.post('/xssTester-scan', testXssPayload);

export default router;
