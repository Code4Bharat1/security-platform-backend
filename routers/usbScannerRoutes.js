import express from "express";
import { scanUSB } from "../controllers/usbScannerController.js";

const router = express.Router();

router.post("/scan-usb", scanUSB);

export default router;
