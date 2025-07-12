// weboptimizer-Router.js
import express from 'express';
import { analyzeWebsite } from '../controllers/weboptimizerController.js';

const router = express.Router();

router.post('/', analyzeWebsite); // listens to POST /api/website-optimization

export default router;
