import express from 'express';
import { upload } from '../middleware/upload.js';
import { scanQRCode, generateQRCode } from '../controllers/qrController.js';

const router = express.Router();
router.post('/scan', upload.single('qrImage'), scanQRCode);
router.post('/generate', generateQRCode);
export default router;
