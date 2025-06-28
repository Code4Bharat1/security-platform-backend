// routers/mdrMonitorRouter.js
import express from "express";
import { monitorSite } from "../controllers/mdrMonitorController.js";

const router = express.Router();

router.post("/", monitorSite);

export default router;
