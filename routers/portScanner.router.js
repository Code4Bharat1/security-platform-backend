import express from "express";

import { portScanHandler } from "../controllers/portScanner.controller.js";
const router = express.Router();

// GET /api/portScan?host=example.com&startPort=80&endPort=100
router.get("/portScan", portScanHandler);

export default router;
