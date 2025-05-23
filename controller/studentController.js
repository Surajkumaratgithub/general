import bcrypt from "bcrypt";
import mongoose from "mongoose";
import Otp from "../model/otpModel.js";
import Student from "../model/studentModel.js";
import User from "../model/userModel.js";
import formatUserData from "../utils/formatInput.js";
import { sendWelcomeEmail } from '../utils/sendWelcomeEmail.js';
import crypto from "crypto";
import { sendOtpEmail } from "../controller/loginController.js"; // adjust your path

// Register new student
// export const registerStudent = async (req, res, next) => {
//   try {
//     const formatData = formatUserData(req.body);
//     if (!formatData.email || !formatData.mobileNumber) {
//       return res
//         .status(400)
//         .json({ error: "email and mobile number required" });
//     }

//     // Check for duplicate email or mobile number
//     const [existingUser, existingStudent] = await Promise.all([
//       User.findOne({
//         $or: [
//           { email: formatData.email },
//           { mobileNumber: formatData.mobileNumber },
//         ],
//       }),
//       Student.findOne({
//         $or: [
//           { email: formatData.email },
//           { mobileNumber: formatData.mobileNumber },
//         ],
//       }),
//     ]);

//     if (existingUser || existingStudent) {
//       const existing = existingUser || existingStudent;
//       let message = "";

//       if (existing.email === formatData.email) {
//         message = "Email already in use.";
//       } else {
//         message = "Mobile number already in use.";
//       }

//       return res.status(400).json({ message });
//     }

//     const record = await Otp.findOne({ email: formatData.email });
//     if (record) {
//       return res.status(400).json({ message: "First Verify Otp" });
//     }

//     // Create new student
//     const student = new Student({
//       name: formatData.name,
//       dob: formatData.dob,
//       email: formatData.email,
//       mobileNumber: formatData.mobileNumber,
//       password: formatData.password,
//     });

//     await student.save();
//     next();
//     res.status(201).json({
//       message: "Student registered successfully",
//     });
//   } catch (error) {
//     res.status(400).json({ error: error.message });
//   }
// };

export const registerStudent = async (req, res) => {
  try {
    const formatData = formatUserData(req.body);

    if (!formatData.email || !formatData.mobileNumber,!formatData.password.trim()) {
      return res.status(400).json({ error: "Email or mobile number and password are required" });
    }

    // Check for duplicate
    const existingUser = await User.findOne({
      $or: [{ email }, { mobileNumber }],
    });

    if (existingUser && existingUser.role!== 'demostudent') {
      const existing = existingUser;
      let message = existing.email === formatData.email ? "Email already in use." : "Mobile number already in use.";
      return res.status(400).json({ message });
    }

    // Generate 6-digit OTP
    const otp = crypto.randomInt(100000, 999999).toString();

    // Delete any existing OTP for this email
    await Otp.findOneAndDelete({ email: formatData.email });

    // Create new OTP record
    await Otp.create({
      email: formatData.email,
      otp,
      verified: false
    });

    // Send OTP to email
    await sendOtpEmail(formatData.email, otp);

    // Store user data temporarily in session or secure storage (for this example using session)
    if (!req.session) {
      req.session = {};
    }

    req.session.pendingStudentRegistration = formatData; // save all formatted data temporarily

    return res.status(200).json({
      success: true,
      message: "OTP sent to your email address. Please verify to complete registration."
    });

  } catch (error) {
    console.error("Register Error:", error);
    res.status(500).json({ error: error.message });
  }
};

// export const verifyStudentOtp = async (req, res) => {
//   try {
//     const { otp } = req.body;

//     if (!otp) {
//       return res.status(400).json({ success: false, message: "OTP is required" });
//     }

//     if (!req.session || !req.session.pendingStudentRegistration) {
//       return res.status(400).json({ success: false, message: "No pending registration found. Please register again." });
//     }

//     const formatData = req.session.pendingStudentRegistration;

//     // Find OTP record
//     const otpRecord = await Otp.findOne({ email: formatData.email, otp });

//     if (!otpRecord) {
//       return res.status(400).json({ success: false, message: "Invalid or expired OTP" });
//     }

//     if (otpRecord.verified) {
//       return res.status(400).json({ success: false, message: "OTP already used. Please request a new OTP." });
//     }

//     // Mark OTP as verified
//     otpRecord.verified = true;
//     await otpRecord.save();

//     // Now create student
//     const student = new Student({
//       name: formatData.name,
//       dob: formatData.dob,
//       email: formatData.email,
//       mobileNumber: formatData.mobileNumber,
//       password: formatData.password,
//     });

//     await student.save();
//     await sendWelcomeEmail(email,name);

//     // Clean up session and OTP
//     delete req.session.pendingStudentRegistration;

//     return res.status(201).json({
//       success: true,
//       message: "Student registered successfully"
//     });

//   } catch (error) {
//     console.error("Verify OTP Error:", error);
//     res.status(500).json({ error: error.message });
//   }
// };



// Get all students




export const verifyStudentOtp = async (req, res) => {
  try {
    const { otp } = req.body;

    if (!otp) {
      return res.status(400).json({ success: false, message: "OTP is required" });
    }

    if (!req.session?.pendingStudentRegistration) {
      return res.status(400).json({ success: false, message: "No pending registration found. Please register again." });
    }

    const formatData = req.session.pendingStudentRegistration;

    const otpRecord = await Otp.findOne({ email: formatData.email, otp });

    if (!otpRecord) {
      return res.status(400).json({ success: false, message: "Invalid or expired OTP" });
    }

    if (otpRecord.verified) {
      return res.status(400).json({ success: false, message: "OTP already used. Please request a new OTP." });
    }

    // Mark OTP as verified
    otpRecord.verified = true;
    await otpRecord.save();
    const hashPass = bcrypt.hash(formatData.password, 10)
    const user = await User.findOneAndUpdate(
  { email: formatData.email },
  {
    $set: {
      email: formatData.email,
      name: formatData.name,
      mobileNumber: formatData.mobileNumber,
      password: hashPass,
      branch: formatData.branch,
      mode: formatData.mode,
      role: 'student'
    }
  },
  {
    new: true,    
    upsert: true,  
  }
);

    
    // Create student
    const student = new Student({
      user: user._id,
        ...formatData
    });

    await student.save();

    // Send welcome email (call utility function)
    await sendWelcomeEmail(formatData.email, formatData.name);

    // Clean session
    delete req.session.pendingStudentRegistration;

    return res.status(201).json({
      success: true,
      message: "Student registered successfully"
    });

  } catch (error) {
    console.error("Verify OTP Error:", error);
    res.status(500).json({ error: error.message });
  }
};


export const getAllStudents = async (req, res) => {
  try {
    const students = await Student.find()
      .select("-password -__v") // Exclude password and __v
      .populate({
        path: "notifications",
        select: "title description sentAt",
      })
      .sort({ createdAt: -1 }); // Sort students by the latest createdAt first

    res.status(200).json({
      success: true,
      count: students.length,
      students,
    });
  } catch (error) {
    console.error("Error fetching students:", error);
    res.status(500).json({
      success: false,
      message: "Failed to retrieve students",
      error: error.message,
    });
  }
};

// Get single student by ID
export const getStudentById = async (req, res) => {
  try {
    const { studentId } = req.params;

    // Validate MongoDB ObjectId format
    if (!mongoose.Types.ObjectId.isValid(studentId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid student ID format",
      });
    }

    const student = await Student.findById(studentId)
      .select("-password -__v") // Exclude password
      .populate({
        path: "notifications",
        select: "title description sentAt",
      });
    if (!student) {
      return res.status(404).json({
        success: false,
        message: "Student not found",
      });
    }

    res.status(200).json({
      success: true,
      student,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Failed to retrieve student",
      error: error.message,
    });
  }
};

// Update student
export const updateStudent = async (req, res) => {
  try {
    const { studentId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(studentId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid student ID",
      });
    }

    const student = await Student.findById(studentId);
    if (!student) {
      return res.status(404).json({
        success: false,
        message: "Student not found",
      });
    }

    const data = formatUserData(req.body);

    // Apply updates
    if (data.name.firstName) student.name.firstName = data.name.firstName;
    if (data.name.lastName) student.name.lastName = data.name.lastName;
    if (data.dob) student.dob = data.dob;
    if (data.email) student.email = data.email;
    if (data.mobileNumber) student.mobileNumber = data.mobileNumber;

    const updateStudent = await student.save();

    console.log(updateStudent);
    res.status(200).json({
      success: true,
      message: "Student updated successfully",
      student: updateStudent,
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      message: "Update failed",
      error: error.message,
    });
  }
};

// Delete student
// Delete student
export const deleteStudent = async (req, res) => {
  try {
    const { studentId } = req.params;

    // Validate ObjectId
    if (!mongoose.Types.ObjectId.isValid(studentId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid student ID",
      });
    }

    const student = await Student.findByIdAndDelete(studentId);

    if (!student) {
      return res.status(404).json({
        success: false,
        message: "Student not found",
      });
    }

    res.status(200).json({
      success: true,
      message: "Student deleted successfully",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message,
    });
  }
};

export const getAllStudentNames = async (req, res) => {
  try {
    const students = await Student.find({}, { _id: 1, name: 1 });

    res.status(200).json({
      message: "Student names fetched successfully",
      data: students,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// API endpoint to verify OTP
export const verifyOtp = async (req, res) => {
  try {
    const { email, otp } = formatUserData(req.body);

    const record = await Otp.findOne({ email });
    if (!record || record.expiresAt < Date.now()) {
      return res.status(400).json({ message: "Invalid or expired OTP" });
    }

    // Compare the hashed OTP with the input OTP
    const isOtpValid = await bcrypt.compare(otp, record.otp);
    if (!isOtpValid) {
      return res.status(400).json({ message: "Invalid OTP" });
    }

    // OTP is valid, delete the record
    await Otp.deleteOne({ email });

    return res.status(200).json({ message: "OTP verify Successfully." });
  } catch (error) {
    console.error("Error in OTP verification:", error);
    res.status(500).json({
      success: false,
      message: "Error during OTP verification",
      error: error.message,
    });
  }
};
