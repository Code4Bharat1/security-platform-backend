// routers/fileScannerRouter.js
import express from "express";
import multer from "multer";
import { scanFile } from "../controllers/fileScannerController.js";

const router = express.Router();
const upload = multer({ dest: "uploads/" });

router.post("/", upload.single("file"), scanFile);

export default router;
