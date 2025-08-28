import { Router } from 'express';
import { convertDomainToIP } from '../controllers/domainToIPController.js';

const router = Router();

// Post route to convert domain to IP
router.post('/convert', convertDomainToIP);

export default router;
