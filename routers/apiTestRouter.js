// backend/routes/apiTestRouter.js
import express from "express";
import { testApi } from "../controllers/apiTestController.js";
const router = express.Router();

router.post("/apitest-scan", testApi);

export default router;