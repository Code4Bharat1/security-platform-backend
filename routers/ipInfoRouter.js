import express from "express";
import { scanLink } from "../controllers/linkDetectorController.js";

const router = express.Router();

// POST /api/link-detector/link-scan
router.post("/link-scan", scanLink);

export default router;
