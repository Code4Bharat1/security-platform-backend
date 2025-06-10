import express from 'express';
import { getWhoisData } from '../controllers/whoisController.js';

const router = express.Router();

router.post('/whois-scan', getWhoisData);

export default router;
