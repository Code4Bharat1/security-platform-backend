import express from 'express';
import { scanWordPress } from '../controllers/wordpressController.js';

const router = express.Router();

router.post('/wordpress-scan', scanWordPress);


export default router;
