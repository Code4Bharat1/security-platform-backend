// routers/folderThreatScanRouter.js
import express from "express";
import multer from "multer";
import { scanFolder } from "../controllers/folderThreatScanController.js";

const router = express.Router();
const upload = multer({ dest: "uploads/" });

router.post("/", upload.array("files"), scanFolder);

export default router;
