import express from "express";
import {
  createReview,
  deleteReview,
  getReview,
  updateReview,
} from "../controller/demoCoursesReviewController.js";
import { accessToRole, isAuth } from "../middleware/authMiddleware.js";

const router = express.Router({ mergeParams: true });

router.post("/", isAuth,accessToRole(['student']), createReview);
router.get("/:reviewId", getReview);
router.put("/:reviewId", updateReview);
router.delete("/:reviewId", deleteReview);

export default router;
