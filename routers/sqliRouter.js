// routers/sqliRouter.js
import express from "express";
import { scanSQLi } from "../controllers/sqliController.js";

const router = express.Router();

router.post("/scan", scanSQLi);

export default router;
