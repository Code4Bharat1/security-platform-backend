import express from "express";
import { scanSQLi } from "../controllers/sqliScannerController.js";

const router = express.Router();

router.post("/sqli-scan", scanSQLi);

export default router;
