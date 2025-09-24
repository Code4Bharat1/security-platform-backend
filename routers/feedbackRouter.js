import { Router } from 'express';
import Page from '../controllers/feedbackController.js';
const router = Router();

router.post('/', Page );
export default router;
