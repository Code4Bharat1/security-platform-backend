// routers/ipInfoRouter.js
import express from 'express';
import { getIpInfo } from '../controllers/ipInfoController.js';

const router = express.Router();
router.post('/', getIpInfo);

export default router;
