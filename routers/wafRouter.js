// routers/wafRouter.js
import express from 'express';

import { detectWAF } from '../controllers/wafController.js'; 
const router = express.Router();

router.post('/waf-scan', detectWAF);

export default router;