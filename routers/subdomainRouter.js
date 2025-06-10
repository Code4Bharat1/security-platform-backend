import express from 'express';
import { findSubdomains } from '../controllers/subdomainController.js';

const router = express.Router();

router.post('/subdomains-scan', findSubdomains);

export default router;
