import express from "express";
import multer from "multer";
import { detectDataLeak } from "../controllers/dataLeakController.js";

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage() });

router.post("/", upload.array("files"), detectDataLeak);

export default router;
