import express from "express";
import { scanRogueWiFi } from "../controllers/rogueWifiController.js";

const router = express.Router();

router.post("/rogue-wifi-scan", scanRogueWiFi);

export default router;
