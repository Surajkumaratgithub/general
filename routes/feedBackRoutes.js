import express from "express";
import { createFeedback, getFeedbackForDemo } from "../controller/feedBackController.js";
const router = express.Router();

router.post("/", createFeedback);
router.get("/:demoClassId", getFeedbackForDemo);

export default router;
