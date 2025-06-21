// routers/ssrfRouter.js
import express from 'express';
import { testSSRF, getSSRFScanHistory, deleteSSRFScan } from '../controllers/ssrfController.js';

const router = express.Router();

router.post('/test', testSSRF);
router.get('/history', getSSRFScanHistory);
router.delete('/delete/:id', deleteSSRFScan);

export default router;