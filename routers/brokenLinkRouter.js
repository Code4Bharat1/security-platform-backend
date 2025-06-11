import express from 'express';
import { streamBrokenLinks } from '../controllers/brokenLinkController.js';

const router = express.Router();

router.get('/brokenlink-stream', streamBrokenLinks);

export default router;
