import express from "express";
import multer from "multer";
import { scanFakeSoftware } from "../controllers/fakeSoftwareController.js";

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage() });

router.post("/fake-software-scan", upload.single("file"), scanFakeSoftware);

export default router;
