import Teacher from "../model/teacherModel.js";
import uploadResumeToCloudinary from "../utils/uploadResumeToCloudinary.js";
import uploadImageToCloudinary from "../utils/uploadImageToCloudinary.js";
import User from "../model/userModel.js";
import Student from "../model/studentModel.js";
import mongoose from "mongoose";
import formatUserData from "../utils/formatInput.js";
import { validateTeacherData } from "../validations/teacher.js";
import { sendPasswordToEmail } from "../middleware/sendPasswordToEmail.js";

const cloudinaryImageFolder = "teachers/profilPhotos"; // teacher profile photos
const cloudinaryResumeFolder = "teachers/resume"; // teacher resume

// Create Teacher (with User and Bank details)
export const createTeacher = async (req, res) => {

  if (!req.body.email.trim().toLowerCase() && req.body.mobileNumber?.trim()) {
    return res.status(400).json("Email and Phone Should not be empty.");
  }

  try {
    // Check for duplicate email or mobile number
    // Normalize input
    const checkEmail = req.body.email?.trim().toLowerCase();
    const checkMobileNumber = req.body.mobileNumber?.trim();

    // Validate presence
    if (!checkEmail) {
      return res.status(400).json({ message: "Email is required" });
    }

    // Check for duplicates in both User and Student collections
    const [existingUser, existingStudent] = await Promise.all([
      User.findOne({
        $or: [{ email: checkEmail }, { mobileNumber: checkMobileNumber }],
      }),
    ]);

    if (existingUser || existingStudent) {
      const existing = existingUser || existingStudent;
      let message = "";

      if (existing.email === checkEmail) {
        message = "Email already in use.";
      } else {
        message = "Mobile number already in use.";
      }

      return res.status(400).json({ message });
    }

    // (excluding photo)
    const { photo, ...userDataWithoutPhoto } = req.body;

    const formatData = formatUserData(userDataWithoutPhoto);
    // validate all data
    const { error } = validateTeacherData(formatData);
    console.log(error);
    if (error) {
      return res
        .status(400)
        .json({ errors: error.details.map((e) => e.message) });
    }

    console.log("Validation passed.");

    const {
      name,
      email,
      mobileNumber,
      password,
      alternativeNumber,
      address,
      dob,
      maritalStatus,
      religion,
      citizenship,
      gender,
      dutyType,
      joiningDate,
      payFrequency,
      payFrequencyText,
      salary,
      hourlyRate,
      // designation,
      branch,
      bankDetails,
      teachingMode,
    } = formatData;

    if (!password) return res.status(400).json({ message: "Need Password" });
    const hashPass = await bcrypt.hash(password, SALT);

    // Create teacher with role is teacher
    const newUser = new User({
      name,
      email,
      mobileNumber,
      branch,
      password:hashPass,
      role: "teacher",
    });
    const savedUser = await newUser.save();

    if (!savedUser)
      return res.status(400).json({ message: "Error creating user" });

    const userId = savedUser._id;

    const photoFile = photo;
    // === Handle files from multer ===
    const resumeFile = req.files?.resume?.[0];

    // init for the photo and resume
    let photoUrl = null;
    let resumeUrl = null;

    // Upload image
    if (photoFile) {
      photoUrl = await uploadImageToCloudinary(
        photoFile,
        cloudinaryImageFolder
      );
    }

    // Upload resume
    if (resumeFile) {
      resumeUrl = await uploadResumeToCloudinary(
        resumeFile.buffer,
        cloudinaryResumeFolder
      );
    }

    // Create teacher
    const newTeacher = new Teacher({
      user: userId,
      alternativeNumber,
      address,
      dob,
      maritalStatus,
      religion,
      citizenship,
      gender,
      dutyType,
      joiningDate,
      payFrequency,
      payFrequencyText,
      salary,
      hourlyRate,
      bankDetails,
      teachingMode,
      photo: photoUrl,
      resume: resumeUrl,
    });

    const savedTeacher = await newTeacher.save();
    const response = await sendPasswordToEmail({
      ...userDataWithoutPhoto,
      role: "teacher",
    });
    if (response) {
      res.status(201).json({
        message: "Teacher created successfully",
        teacher: savedTeacher,
      });
    }
  } catch (error) {
    console.error("Error in createTeacher:", error);
    res.status(500).json({
      message: "Error creating teacher",
      error: error.message,
    });
  }
};

// Get All Teachers
export const getTeachers = async (req, res) => {
  try {
    const teachers = await Teacher.find()
      .populate("user", "name email mobileNumber")
      .populate("notifications", "title description createdAt"); // Add this line

    res.status(200).json({ count: teachers.length, teachers });
  } catch (error) {
    console.error("Error in getAllTeachers:", error);
    res
      .status(500)
      .json({ message: "Failed to fetch teachers", error: error.message });
  }
};

// Get a single Teacher by ID
export const getTeacherById = async (req, res) => {
  try {
    const { teacherId } = req.params;
    if (!mongoose.Types.ObjectId.isValid(teacherId)) {
      return res.status(400).json({ message: "Invalid teacher ID" });
    }

    const teacher = await Teacher.findById(teacherId)
      .populate("user", "name email mobileNumber")
      .populate("notifications", "title description createdAt"); // Add this line

    if (!teacher) return res.status(404).json({ message: "Teacher not found" });

    res.status(200).json({ success: true, teacher });
  } catch (error) {
    console.error("Error in getTeacherById:", error);
    res.status(500).json({
      success: true,
      message: "Failed to fetch teacher",
      error: error.message,
    });
  }
};

// Update Teacher
export const updateTeacher = async (req, res) => {
  const { teacherId } = req.params;

  if (!mongoose.Types.ObjectId.isValid(teacherId)) {
    return res.status(400).json({
      success: false,
      message: "Invalid teacher ID format.",
    });
  }

  try {
    // Fetch teacher and check
    const teacher = await Teacher.findById(teacherId);
    if (!teacher) return res.status(404).json({ message: "Teacher not found" });

    const user = await User.findById(teacher.user);
    if (!user)
      return res.status(404).json({ message: "Linked user not found" });

    // (excluding photo)
    const { photo, ...userDataWithoutphoto } = req.body;

    // Format and validate input
    const formatData = formatUserData(userDataWithoutphoto);
    const { error } = validateTeacherData(formatData);

    if (error) {
      return res.status(400).json({
        errors: error.details.map((e) => e.message),
      });
    }

    const {
      name, // need to discuss
      email,
      mobileNumber,
      password,
      alternativeNumber,
      address,
      dob,
      maritalStatus,
      religion,
      citizenship,
      gender,
      dutyType,
      joiningDate,
      payFrequency,
      payFrequencyText,
      salary,
      hourlyRate,
      bankDetails,
      emergencyContact,
      teachingMode,
    } = formatData;

    const photoFile = photo;
    // === Handle files from multer ===
    const resumeFile = req.files?.resume?.[0];

    let photoUrl = teacher.photo;
    let resumeUrl = teacher.resume;

    if (photoFile) {
      photoUrl = await uploadImageToCloudinary(
        photoFile,
        cloudinaryImageFolder
      );
    }

    if (resumeFile) {
      resumeUrl = await uploadResumeToCloudinary(
        resumeFile.buffer,
        cloudinaryResumeFolder
      );
    }

    // // this need to discuss
    user.name = name;
    user.email = email;
    user.mobileNumber = mobileNumber;
    if (password) user.password = password;
    await user.save();

    // Update Teacher data
    Object.assign(teacher, {
      name,
      email,
      mobileNumber,
      password,
      alternativeNumber,
      address,
      dob,
      maritalStatus,
      religion,
      citizenship,
      gender,
      dutyType,
      joiningDate,
      payFrequency,
      payFrequencyText,
      salary,
      hourlyRate,
      // designation,
      bankDetails,
      emergencyContact,
      teachingMode,
      photo: photoUrl,
      resume: resumeUrl,
    });

    const updatedTeacher = await teacher.save();

    res.status(200).json({
      message: "Teacher updated successfully",
      updatedTeacher,
    });
  } catch (error) {
    console.error("Error in updateTeacher:", error);
    res.status(500).json({
      message: "Error updating teacher",
      error: error.message,
    });
  }
};

// Change Teacher Status (Active, Resigned, Terminated)
export const changeTeacherStatus = async (req, res) => {
  try {
    const { status } = req.body;
    const { teacherId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(teacherId)) {
      return res.status(400).json({ message: "Invalid teacher ID" });
    }

    const allowedStatuses = ["Active", "Resigned", "Terminated"];
    if (!allowedStatuses.includes(status?.trim())) {
      return res.status(400).json({
        message:
          "Invalid status. Allowed values: 'Active', 'Resigned', 'Terminated'",
      });
    }

    const updatedTeacher = await Teacher.findByIdAndUpdate(
      teacherId,
      { status: status.trim() },
      { new: true }
    );

    if (!updatedTeacher) {
      return res.status(404).json({ message: "Teacher not found" });
    }

    res.status(200).json({
      message: `Teacher status updated to '${updatedTeacher.status}'`,
      teacher: updatedTeacher,
    });
  } catch (error) {
    console.error("Error changing teacher status:", error);
    res.status(500).json({
      message: "Server error while changing teacher status",
      error: error.message,
    });
  }
};

export const getAllTeacherNames = async (req, res) => {
  try {
    const teachers = await Teacher.find({}, { _id: 1, user: 1 })
      .populate("user", "name")
      .select("_id user");
      console.log("teachers is:",teachers);

    const teacherNames = teachers
    .filter(teacher => teacher?.user?.name?.firstName && teacher?.user?.name?.lastName)
    .map(teacher => `${teacher.user.name.firstName} ${teacher.user.name.lastName}`);



    // const teacherNames = teachers.map((teacher) => ({
    //   _id: teacher._id,
    //   name: teacher.user.name,
    // }));

    // const teacherNames = teachers
    // .filter(teacher => teacher && teacher.name)
    // .map(teacher => teacher.name);

    console.log("teachere Namses are",teacherNames);

    res.status(200).json({
      message: "Teacher names fetched successfully",
      count: teachers.length,
      data: teacherNames,
    });
  } catch (error) {
    console.error("Error fetching teacher names:", error);
    res.status(500).json({ error: error.message });
  }
};
