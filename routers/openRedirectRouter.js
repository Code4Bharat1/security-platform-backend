import express from 'express';
import { testOpenRedirect } from '../controllers/openRedirectController.js';
//
const router = express.Router();

router.post('/openRedirect-tester', testOpenRedirect);

export default router;
