import express from 'express';
import { getIpInfo } from '../controllers/ipInfoController.js';

const router = express.Router();
// router.post('/ip-info', getIpInfo);

router.post('/ip-info', (req, res, next) => {
  console.log("🔥 /api/ipinfo/ip-info route hit");
  next();
}, getIpInfo);


export default router;
