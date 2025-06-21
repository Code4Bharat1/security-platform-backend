import express from 'express';
import { suggestSecurityHeaders } from '../controllers/securityHeadersAI.js';

const router = express.Router();

router.post('/suggest-headers', suggestSecurityHeaders);

export default router;
