// routers/thirdPartyPermissionRouter.js
import express from "express";
import { scanAppPermissions } from "../controllers/thirdPartyPermissionController.js";

const router = express.Router();
router.post("/permission-scan", scanAppPermissions);

export default router;
