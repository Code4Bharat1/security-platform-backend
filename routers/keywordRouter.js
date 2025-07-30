import express from 'express';
import { generateKeywords } from '../controllers/seoKeywordController.js';


const router = express.Router();

router.post('/generate', generateKeywords);

export default router;
