// routers/nexposeRouter.js
import express from "express";
import { scanSQLi } from "../controllers/sqliController.js";

const router = express.Router();

router.post("/sql", scanSQLi);

export default router;
