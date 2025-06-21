import express from 'express';
import { deleteScanById, getScanHistory, testBrokenAccessControl } from '../controllers/brokenAccessController.js';
import { getBrokenAccessReports } from '../controllers/getBrokenAccessReports.js';

const router = express.Router();

router.post('/broken-test', testBrokenAccessControl);
router.get('/reports', getBrokenAccessReports);
router.get('/scan-history', getScanHistory);
router.delete('/delete/:id',deleteScanById);
export default router;
