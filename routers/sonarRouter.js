// routers/sonarRouter.js
import express from 'express';
import { analyzeCode } from '../controllers/sonarController.js';

const router = express.Router();

router.post('/sonar_analyze', analyzeCode);

export default router;
