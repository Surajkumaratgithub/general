import express from "express";
import demoCoursesRoutes from "./demoCoursesReviewRoutes.js";
import {
  createDemoCourse,
  getAllDemoCourses,
  updateDemoCourse,
  deleteDemoCourse,
  getDemoCoursesById,
  bookSeat,
  addTeacherToDemoCourse,
} from "../controller/demoCoursesController.js";

const router = express.Router({ mergeParams: true });

router.post("/create", createDemoCourse);
router.post("/add-teachers", addTeacherToDemoCourse);
router.get("/getAllDemoCourse", getAllDemoCourses);
router.get("/:demoCourseId", getDemoCoursesById);
router.put("/:demoCourseId", updateDemoCourse);
router.delete("/:demoCourseId", deleteDemoCourse);
router.post("/:demoCourseId/book",  bookSeat);
// all reviews routes
router.use("/:demoCourseId/reviews", demoCoursesRoutes);
export default router;
