// routers/fileScannerRouter.js

import { Router } from "express";
import multer from "multer";
import { scanFile } from "../controllers/fileScannerController.js";  // Correct ES module import

const router = Router();

// Set up Multer for file upload
const upload = multer({ dest: "uploads/" });  // Store files in "uploads" folder

// Define the route for scanning files
router.post("/scan", upload.single("file"), scanFile);  // Expect a single file uploaded with the field name "file"

export default router;
