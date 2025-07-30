// routers/whatsappPrivacyRouter.js
import express from "express";
import whatsappPrivacyInspectorController from "../controllers/whatsappPrivacyInspectorController.js";
import { upload } from '../middleware/upload.js';

const router = express.Router();

router.post("/inspect", upload.array('images', 2), whatsappPrivacyInspectorController);

export default router;
