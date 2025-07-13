import express from 'express';
import { analyzeSEO } from '../controllers/seoController.js';

const router = express.Router();

// Route: POST /api/seo/analyze
router.post('/analyze', analyzeSEO);

export default router;
