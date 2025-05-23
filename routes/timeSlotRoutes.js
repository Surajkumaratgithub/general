import express from "express";
import { addTeacherTimeSlots, getAvailableSlots } from "../controller/timeSlotController.js";
import { accessToRole, isAuth } from "../middleware/authMiddleware.js";
const router = express.Router();


router.post('/add', addTeacherTimeSlots)
router.post('/get-slots',getAvailableSlots)


export default router