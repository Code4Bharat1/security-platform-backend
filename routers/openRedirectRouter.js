// routes/openRedirect.routes.js
import express from 'express';
import { testOpenRedirectAdvanced } from '../controllers/openRedirectController.js';
const router = express.Router();
router.post('/openRedirect-tester-advanced', testOpenRedirectAdvanced);
export default router;
