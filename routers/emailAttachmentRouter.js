import express from 'express';
import multer from 'multer';
import { analyzeEmailAttachment } from '../controllers/emailAttachmentController.js';

const router = express.Router();
const upload = multer({ dest: "uploads/" });

router.post("/", upload.single("file"), analyzeEmailAttachment);

export default router;
