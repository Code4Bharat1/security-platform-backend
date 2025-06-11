import express from 'express';

import { scanSharePoint } from '../controllers/sharePointController.js';
const router=express.Router();
router.post('/sharepoint-scanner', scanSharePoint);

export default router;