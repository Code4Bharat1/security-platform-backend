// routes/dnsRoutes.js (example)
import { Router } from 'express';
import { resolveDNS, reconScan } from '../controllers/dnsController.js';

const router = Router();
router.post('/dns/resolve', resolveDNS);
router.post('/dns/recon-scan', reconScan);
export default router;
