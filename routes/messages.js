import express from "express";
import { sendMessage, getMessage } from "../controllers/message.controller.js";
import { isAuth } from "../middlewares/isAuth.js";

const router = express.Router();

// Message Routes
router.post("/send/:id", isAuth, sendMessage);
router.get("/messages/:id", isAuth, getMessage);

export default router;
