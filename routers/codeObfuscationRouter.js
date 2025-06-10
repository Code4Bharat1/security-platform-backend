// routers/codeObfuscationRouter.js
import express from 'express';
import { analyzeCodeObfuscation } from '../controllers/codeObfuscationController.js';

const router = express.Router();

router.post('/code-obfuscation', analyzeCodeObfuscation);

export default router;
