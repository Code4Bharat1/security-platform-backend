// routers/scanRouter.js
import express from 'express';
import { runScan } from '../controllers/scanController.js'; // make sure path is correct

const router = express.Router();

router.post('/run-scan', runScan); // ✅ defines POST /api/scan/run-scan

export default router;
