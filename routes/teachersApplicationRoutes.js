import express from "express";
import {
  applicationDelete,
  getAllApplications,
  getApplicationById,
  newApplication,
  updateTeacherApplicationStatus,
} from "../controller/teachersApplicationController.js";

import uploadMiddleware from "../middleware/uploadMiddleware.js";

const router = express.Router();

router.get("/getAllApplications", getAllApplications);
router.post("/", uploadMiddleware, newApplication);
// If rejected
router.patch("/:teacherApplicationId", updateTeacherApplicationStatus);
router.delete("/deleteAppliccation/:id",applicationDelete);
router.get("/getApplicationById/:id", getApplicationById);
export default router;

// We will not give edit button once the application is submit.
