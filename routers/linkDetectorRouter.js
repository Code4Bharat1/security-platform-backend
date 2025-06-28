import express from "express";
import { scanLink } from "../controllers/linkDetectorController.js";

const router = express.Router();

router.post("/link-scan", scanLink);

export default router;
