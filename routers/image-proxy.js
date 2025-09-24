import express from 'express';
import handler from '../controllers/image-proxy.js';
const router = express.Router();

router.get('/image-proxy', handler );
export default router;
