import express from 'express';
import multer from 'multer';
import { generateQRController, scanQRController } from '../controllers/qrController.js';

const upload = multer({ dest: 'uploads/' });
const router = express.Router();

router.post('/generate', generateQRController);
router.post('/scan', upload.single('qrImage'), scanQRController);

export default router;
