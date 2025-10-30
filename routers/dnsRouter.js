// routes/dnsRoutes.js (example)
import { Router } from 'express';
import { resolveDNS, reconScan } from '../controllers/dnsController.js';

const router = Router();
router.post('/resolve', resolveDNS);
router.post('/recon-scan', reconScan);
export default router;
