import express from "express";
import { scanRogueWiFi } from "../controllers/rogueWiFiController.js";

const router = express.Router();

router.post("/rogue-wifi-scan", scanRogueWiFi);

export default router;
