// routers/whatsappPrivacyRouter.js
import express from "express";
import { inspectPrivacy } from "../controllers/whatsappPrivacyController.js";

const router = express.Router();

router.post("/", inspectPrivacy);

export default router;
