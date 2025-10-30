// routers/analysisRouter.js
import express from 'express';

import { analyzeCode } from '../controllers/analysisController.js';
const router = express.Router();

router.post('/analyze-scan', analyzeCode);

export default router;
