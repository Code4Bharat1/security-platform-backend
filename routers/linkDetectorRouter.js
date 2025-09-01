import express from "express";
import { bulkScan, scanLink } from "../controllers/linkDetectorController.js";

const router = express.Router();

router.post("/link-scan", scanLink);

router.post("/bulk-scan",bulkScan)

export default router;
