import express from "express";

import {
  submitAssignment,
  getSubmissionsByAssignment,
  getStudentSubmission,
  evaluateSubmission,
} from "../controller/assignmentSubmissionController.js";

import uploadMiddleware from "../middleware/uploadMiddleware.js";

import { accessToRole, isAuth } from "../middleware/authMiddleware.js";

const router = express.Router();
// Assignment Submission for courses
router.post(
  "/submit/:assignmentId",
  uploadMiddleware,
  submitAssignment
);

router.get("/submissions/:assignmentId", isAuth,accessToRole(['teacher']), getSubmissionsByAssignment);
router.get(
  "/submission/:assignmentId/student/:studentId",
 isAuth,accessToRole(['teacher']),
  getStudentSubmission
);

router.patch("/evaluate/:submissionId", isAuth,accessToRole(['teacher']), evaluateSubmission);

export default router;
