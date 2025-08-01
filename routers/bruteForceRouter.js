// routers/bruteForceRouter.js
import express from 'express';
import { bruteForceScan } from '../controllers/bruteForceController.js';

const router = express.Router();
router.post('/brute-Force', bruteForceScan);

export default router;
