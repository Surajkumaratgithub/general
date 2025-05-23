import express from "express";

import {
  createAdmission,
  getAllAdmissions,
  getAdmissionById,
  deleteAdmission,
} from "../controller/admissionController.js";

const router = express.Router();

// Create a new admission
router.post("/createAdmission", createAdmission);

// Get all admissions
router.get("/getAllAdmissions", getAllAdmissions);

// Get a specific admission by ID
router.get("/getAdmissionById/:id", getAdmissionById);

// Delete an admission by ID
router.delete("/deleteAdmission/:id", deleteAdmission);

export default router;
