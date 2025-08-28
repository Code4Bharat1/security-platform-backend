import { Router } from "express";
import { analyzePassword } from "../controllers/passwordSterengthController.js";
const router = Router();

router.post("/analyze", analyzePassword);

export default router;
