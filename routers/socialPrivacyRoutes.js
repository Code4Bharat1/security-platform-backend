import express from "express";
import { analyzeProfile } from "../controllers/socialPrivacyController.js";

const router = express.Router();

router.post("/social-analyze", analyzeProfile);

export default router;
