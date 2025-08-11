// routes/sourceCodeRoutes.js
import express from "express";
import { scanSourceCode } from "../controllers/sourceCodeController.js";

const router = express.Router();

router.post("/analyze-code", scanSourceCode);

export default router;
