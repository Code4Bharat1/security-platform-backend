import express from 'express';
import { checkOsint } from '../controllers/osintController.js';

const router = express.Router();

router.post('/check', checkOsint);

export default router;
