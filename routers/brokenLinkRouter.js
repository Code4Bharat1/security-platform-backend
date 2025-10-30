import express from 'express';
import { streamBrokenLinks } from '../controllers/brokenLinkController.js';
import sseAuthMiddleware from '../middleware/sseAuthMiddleware.js';
import { checkCredits } from '../middleware/checkCredits.js';

const router = express.Router();

router.get('/brokenlink-stream', sseAuthMiddleware, checkCredits(1), streamBrokenLinks);

export default router;
