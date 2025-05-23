import express from "express";
import { bookADemo, getAllDemoBookings, getBookingByFilters, getDemoBookingByCouseId, getDemoBookingById, getDemoBookingByTeacherId } from "../controller/demoBookingController.js";


const router = express.Router();

// POST book a demo slot
router.post("/book", bookADemo);

// GET all bookings
router.get("/", getAllDemoBookings);
// GET bookings by courseId, teacherId, date range
router.get("/filter", getBookingByFilters);
// GET Booking by ID
router.get("/:id", getDemoBookingById);

// GET bookings by Teacher ID
router.get("/teacher/:teacherId", getDemoBookingByTeacherId);

// GET bookings by Course ID
router.get("/course/:courseId", getDemoBookingByCouseId);

export default router;
