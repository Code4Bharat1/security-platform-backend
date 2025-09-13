import express from 'express';
import { blogs } from '../controllers/blogs.js';
const router = express.Router();

router.get('/', blogs );
export default router;
