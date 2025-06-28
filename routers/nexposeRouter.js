// routers/nexposeRouter.js
import express from "express";
import { scanForSQLi } from "../controllers/nexposeController.js";

const router = express.Router();

router.post("/", scanForSQLi);

export default router;
