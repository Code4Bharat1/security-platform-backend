import express from 'express';
import { upload } from '../middleware/upload.js';
import { scanQRCode } from '../controllers/qrController.js';

const router = express.Router();
router.post('/scan', upload.single('qrImage'), scanQRCode);
export default router;
