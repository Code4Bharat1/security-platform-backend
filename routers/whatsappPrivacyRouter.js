// routers/whatsappPrivacyRouter.js
import express from "express";
import whatsappPrivacyInspectorController from "../controllers/whatsappPrivacyInspectorController.js";
import { upload } from '../middleware/upload.js';

const router = express.Router();

router.post("/", upload.fields([{ name: 'image1', maxCount: 1 },{ name: 'image2', maxCount: 1 }]), whatsappPrivacyInspectorController);

export default router;
