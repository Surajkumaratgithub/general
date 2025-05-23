import TeacherApplication from "../model/teachersApplicationModel.js";
import uploadImageToCloudinary from "../utils/uploadImageToCloudinary.js";
import uploadResumeToCloudinary from "../utils/uploadResumeToCloudinary.js";
import uploadVideoToCloudinary from "../utils/uploadvideoToCloudinary.js";
import mongoose from "mongoose";
import formatUserData from "../utils/formatInput.js";
import { validateTeacherApplication } from "../validations/teacherApplication.js";

const profileFolderLocation = "Teachers-applications/profiles";
const resumeFolderLocation = "Teachers-applications/resume";
const intro_videoFolderLocation = "Teachers-applications/intro-videos";

// New Teacher Application
export const newApplication = async (req, res) => {
  try {
    // (excluding photo)
    const { photo, ...userDataWithoutPhoto } = req.body;
    const formatData = formatUserData(userDataWithoutPhoto);
    // validate all data
    const { error } = validateTeacherApplication(formatData);

    if (error) {
      return res
        .status(400)
        .json({ errors: error.details.map((e) => e.message) });
    }

    console.log("Validation passed.");

    const existingTeacherApp = await TeacherApplication.findOne({
      email: req.body.email.toLowerCase(), // Ensure email is in lowercase for case-insensitive comparison
    });

    if (existingTeacherApp) {
      return res.status(400).json({ message: "You already applied" });
    }

    // Exclude photo from req.body
    // const { photo, ...userDataWithoutPhoto } = req.body;

    // Pass the remaining fields to formatUserData
    const {
      name,
      address,
      mobileNumber,
      email,
      description,
      experience,
      teachingMode,
      skill,
      languages,
      status,
    } = formatData;

    // === Handle files from multer ===
    const resumeFile = req.files?.resume?.[0];
    const videoFile = req.files?.videoConsent?.[0];

    let photoUrl = null;
    let resumeUrl = null;
    let videoUrl = null;

    // Upload base64 photo
    if (photo) {
      photoUrl = await uploadImageToCloudinary(photo, profileFolderLocation); // base64 image
    }

    // Upload resume (buffer)
    if (resumeFile) {
      resumeUrl = await uploadResumeToCloudinary(
        resumeFile.buffer,
        resumeFolderLocation
      );
    }

    // Upload video (buffer)
    if (videoFile) {
      videoUrl = await uploadVideoToCloudinary(
        videoFile.buffer,
        intro_videoFolderLocation
      );
    }

    // Ensure languages is an array
    const languagesArray = Array.isArray(languages)
      ? languages
      : [languages || "English"];

    // === Create teacher application ===
    const teacher = await TeacherApplication.create({
      name,
      address,
      mobileNumber,
      email,
      description,
      experience,
      teachingMode,
      skill,
      status,
      languages: languagesArray,
      photo: photoUrl,
      resume: resumeUrl,
      videoConsent: videoUrl,
    });

    res.status(201).json({ success: true, teacher });
  } catch (error) {
    console.error("Error in newApplication:", error);
    res.status(500).json({
      success: false,
      message: "Something went wrong while submitting application.",
      error: error.message,
    });
  }
};

// Get all Applications
export const getAllApplications = async (req, res) => {
  try {
    // Fetch all teacher applications
    const teacherApplications = await TeacherApplication.find();
    res.status(200).json({
      success: true,
      count: teacherApplications.length,
      applications: teacherApplications,
    });
  } catch (error) {
    console.error("Error in getApplications:", error);
    res.status(500).json({
      success: false,
      message: "Something went wrong while fetching applications.",
      error: error.message,
    });
  }
};

// Get single Application by ID
export const getApplicationById = async (req, res) => {
  const { id } = req.params; // Retrieve the ID from URL params

  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({
      success: false,
      message: "Invalid application ID format.",
    });
  }

  try {
    // Fetch teacher application by ID
    const teacherApplication = await TeacherApplication.findById(id);

    if (!teacherApplication) {
      return res.status(404).json({
        success: false,
        message: "Teacher application not found.",
      });
    }

    res.status(200).json({ success: true, application: teacherApplication });
  } catch (error) {
    console.error("Error in getApplicationById:", error);
    res.status(500).json({
      success: false,
      message: "Something went wrong while fetching the application.",
      error: error.message,
    });
  }
};

// When the Profile Rejected
export const applicationDelete = async (req, res) => {
  const { id } = req.params; // Retrieve the ID from URL params

  try {
    // Find and delete the application by ID
    const deletedApplication = await TeacherApplication.findByIdAndDelete(id);

    if (!deletedApplication) {
      return res.status(404).json({
        success: false,
        message: "Teacher application not found.",
      });
    }

    res.status(200).json({
      success: true,
      message: "Teacher application deleted successfully.",
    });
  } catch (error) {
    console.error("Error in deleteApplication:", error);
    res.status(500).json({
      success: false,
      message: "Something went wrong while deleting the application.",
      error: error.message,
    });
  }
};

export const updateTeacherApplicationStatus = async (req, res) => {
  try {
    const { teacherApplicationId } = req.params;
    const { status } = req.body;

    if (!mongoose.Types.ObjectId.isValid(teacherApplicationId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid application ID format.",
      });
    }

    // Validate the status
    const validStatuses = ["pending", "accept", "reject", "interview"];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ message: "Invalid status value" });
    }

    const updatedTeacher = await TeacherApplication.findByIdAndUpdate(
      teacherApplicationId,
      { status },
      { new: true }
    );

    if (!updatedTeacher) {
      return res.status(404).json({ message: "Teacher not found" });
    }

    res.status(200).json({
      message: "Application status updated successfully",
      teacher: updatedTeacher,
    });
  } catch (error) {
    console.error("Error updating teacher status:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};
