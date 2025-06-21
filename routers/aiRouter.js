import express from 'express';
import { explainVulnerability } from '../controllers/aiController.js';
const router = express.Router();

router.post('/explain', explainVulnerability);

export default router;
