import express from "express";
import {
  createCourse,
  getAllCourses,
  getCourseById,
  updateCourse,
  deleteCourse,
  assignedTeachers,
  changeCourseStatus,
  createSession,
  getSessionsByCourse,
  updateSession,
  deleteSession,
  createClass,
  getClassesBySession,
  updateClass,
  deleteClass,
} from "../controller/courseController.js";

import {
  createAssignment,
  updateAssignment,
  getAssignmentsByCourse,
  deleteAssignment,
  getAssignmentById,
} from "../controller/assignmentController.js";

const router = express.Router({ mergeParams: true });

router.post("/create", createCourse);
router.get("/getAllCourses", getAllCourses);
router.get("/getCourseById/:courseId", getCourseById);
router.put("/:courseId/change-Status", changeCourseStatus);
router.put("/updateCourse/:courseId", updateCourse);
router.delete("/delete/:courseId", deleteCourse);
router.post("/assign-course", assignedTeachers);

// Session Routes under Course
router.post("/courses/:courseId/sessions", createSession);
router.get("/courses/:courseId/sessions", getSessionsByCourse);
router.put("/courses/:courseId/sessions/:sessionId", updateSession);
router.delete("/courses/:courseId/sessions/:sessionId", deleteSession);

// Class Routes under Session under Course
router.post("/courses/:courseId/sessions/:sessionId/classes", createClass);
router.get(
  "/courses/:courseId/sessions/:sessionId/classes",
  getClassesBySession
);
router.put(
  "/courses/:courseId/sessions/:sessionId/classes/:classId",
  updateClass
);
router.delete(
  "/courses/:courseId/sessions/:sessionId/classes/:classId",
  deleteClass
);

// Assignment for courses

router.post("/:courseId/assignments",  createAssignment);
router.put("/:courseId/assignments/:assignmentId", updateAssignment);

// for all assigment of courses
router.get("/:courseId/assignments", getAssignmentsByCourse);

// for specific assignment of courses
router.get("/:courseId/assignments/:assignmentId", getAssignmentById);
router.delete(
  "/:courseId/assignments/:assignmentId",
  deleteAssignment
);

export default router;
