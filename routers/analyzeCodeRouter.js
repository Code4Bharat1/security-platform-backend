// routes/analyzeCodeRouter.js
import express from 'express';
import { analyzeCode } from '../controllers/analyzeCodeController.js';

const router = express.Router();

router.post('/analyzeCode', analyzeCode);

export default router;
