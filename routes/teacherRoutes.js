import express from "express";
import {
  createTeacher,
  getTeacherById,
  getTeachers,
  updateTeacher,
  changeTeacherStatus,
  getAllTeacherNames,
} from "../controller/teacherController.js";
import uploadMiddleware from "../middleware/uploadMiddleware.js";
const router = express.Router();

router.post("/create", uploadMiddleware, createTeacher);
router.get("/getTeacher", getTeachers);
router.get("/names", getAllTeacherNames);
router.get("/:teacherId", getTeacherById);
router.put("/:teacherId", uploadMiddleware, updateTeacher);
router.patch("/status/:teacherId", changeTeacherStatus);

export default router;
