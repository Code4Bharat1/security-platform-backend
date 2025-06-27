import express from "express";
import { scanRogueWifi } from "../controllers/rogueWifiController.js";

const router = express.Router();

router.get("/rogue-wifi", scanRogueWifi);

export default router;
