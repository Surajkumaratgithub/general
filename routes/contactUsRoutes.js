import express from "express";
import {
  submitContactUsForm,
  deleteContactUs,
  getAllContactUs,
  updateContactUsStatus,
} from "../controller/contactUsController.js";

const router = express.Router();
// Create a new admission
router.post("/submit", submitContactUsForm);

// Get all admissions
router.get("/getAll", getAllContactUs);

// Delete an admission by ID
router.delete("/delete/:contactId", deleteContactUs);

router.patch("/update/:contactId", updateContactUsStatus);
export default router;
