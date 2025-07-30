import express from "express";
import { getIpInfo } from "../controllers/ipInfoController.js"

const router = express.Router();

// POST /api/link-detector/link-scan
router.post("/", getIpInfo);

export default router;
