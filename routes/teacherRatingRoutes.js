// routes/teacherRatingRoutes.js
import express from "express";
import {
  createRating,
  getRatingsForTeacher,
  getAverageRating,
} from "../controller/teacherRatingController.js";


const router = express.Router();

router.post("/",  createRating);
router.get("/teacher/:teacherId", getRatingsForTeacher);
router.get("/teacher/:teacherId/average", getAverageRating);

export default router;
