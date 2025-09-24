import express from "express";
import schedulemetting from "../controllers/schedulemeetingController.js";

const router = express.Router();

router.post("/", schedulemetting);

export default router;
