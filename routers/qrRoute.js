import express from "express";
import multer from "multer";
import { generateQRController, scanQRController } from "../controllers/qrController.js";

const router = express.Router();
const upload = multer({ dest: "uploads/" });

router.post("/generate", generateQRController);
router.post("/scan", upload.single("qrImage"), scanQRController);

export default router;
