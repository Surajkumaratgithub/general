import express from "express";
import {
  createNotification,
  getAllNotifications,
  deleteNotification,
} from "../controller/notificationController.js";


const router = express.Router();

router.post("/createNotification",createNotification);

router.get("/", getAllNotifications);

// router.get("/:id", getNotificationById);

router.delete("/delete/:id", deleteNotification);

export default router;
