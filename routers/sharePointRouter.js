import express from 'express';

import { scanSharePoint } from '../controllers/SharePointController.js';
const router=express.Router();
router.post('/sharepoint-scanner', scanSharePoint);

export default router;