// routers/johnRouter.js
import express from "express";
import { crackHash } from "../controllers/johnController.js";

const router = express.Router();

router.post("/", crackHash); // ✅ Make sure this is POST

export default router;
