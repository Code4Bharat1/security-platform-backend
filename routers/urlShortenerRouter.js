import express from 'express';
import { createShortUrl, redirectToOriginalUrl } from '../controllers/urlShortenerController.js';

const router = express.Router();

router.post('/shorten', createShortUrl);

// redirect route
router.get('/:code', redirectToOriginalUrl);

export default router;
