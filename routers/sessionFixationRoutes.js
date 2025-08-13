import { Router } from 'express';
import { analyzeSessionFixation, exportSessionFixation } from '../controllers/sessionFixationController.js';

const router = Router();

router.post('/sessionFixationChecker', analyzeSessionFixation);
router.get('/sessionFixationChecker/export/:id', exportSessionFixation);

export default router;
