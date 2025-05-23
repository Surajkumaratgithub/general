import express from "express";
import {
  registerStudent,
  // loginStudent,
  verifyStudentOtp,
  getAllStudents,
  getStudentById,
  updateStudent,
  deleteStudent,
  verifyOtp,
  getAllStudentNames,
} from "../controller/studentController.js";
import sessionMiddleware from "../config/sessionConfig.js";
import { sendOtp } from "../controller/sendOtp.js";


const router = express.Router();

router.post("/register",sessionMiddleware, registerStudent);

router.post("/verifyStudentOtp",sessionMiddleware, verifyStudentOtp); // this is only for registration email verify(not for login)
router.get("/", getAllStudents);
router.get("/names", getAllStudentNames);
router.get("/:studentId", getStudentById);
router.put("/:studentId", updateStudent);
router.delete("/:studentId", deleteStudent);

export default router;
