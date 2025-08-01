// routers/oauth.router.js
import express from 'express';
import { login, signup, inspectToken } from '../controllers/oauthController.js';

const router = express.Router();

router.post("/login", login);
router.post("/signup", signup);
router.post("/oauthTokenInspector", inspectToken); // new

export default router;
