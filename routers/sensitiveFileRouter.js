import express from 'express';
import { checkSensitiveFiles } from '../controllers/sensitiveFileController.js';

const router = express.Router();

router.post('/check', checkSensitiveFiles);

export default router;
