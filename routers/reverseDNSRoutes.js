import express from 'express';
import { reverseDNSLookup } from '../controllers/reverseDNSController.js';

const router = express.Router();

router.post('/reverse-dns', reverseDNSLookup);

export default router;
         