import express from "express";
import { scanPortActivity } from "../controllers/portActivityController.js";

const router = express.Router();

router.post("/scan-port-activity", scanPortActivity);

export default router;
