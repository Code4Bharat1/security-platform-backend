// routes/sitemapRoutes.js
import express from 'express';

import { generateSitemap } from '../controllers/sitemapController.js';
const router = express.Router();

router.post('/sitemap-scanner', generateSitemap);

export default router;
