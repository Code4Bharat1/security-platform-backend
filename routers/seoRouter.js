import express from 'express';
import { analyzeSEO } from '../controllers/seoController.js';

const router = express.Router();

router.post('/analyze', analyzeSEO);

export default router;
