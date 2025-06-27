// backend/routes/keywordRoutes.js

import express from "express";

import { analyzeKeyword } from "../controllers/keywordController.js";
const router = express.Router();

router.post("/analyze", analyzeKeyword);

export default router;
    