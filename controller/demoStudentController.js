import User from "../model/userModel.js";
import { sendDemoWelcomeEmail } from "../utils/demoStudentEmail.js";

export const registerForDemo = async (req, res) => {
  try {
    const { name, email, mobileNumber } = req.body;

    if (!name || !email || !mobileNumber) {
      return res.status(400).json({ error: "All fields are required." });
    }

    const studentExist = await User.findOne({
      $or: [{ email }, { mobileNumber }],
    });

    if (studentExist) {
      return res.status(400).json({ error: "Email Id or mobileNumber already in use" });
    }

    const student = new User({
      name,
      email,
      mobileNumber,
      role: "demostudent",
    });

    const savedStudent = await student.save();

    // Send welcome email
    await sendDemoWelcomeEmail({
      to: email,
      name,
    });

    res.status(201).json({
      message: "Registered for demo successfully",
      data: savedStudent,
    });
  } catch (err) {
    console.error("Register error:", err.message);
    res.status(500).json({ error: err.message });
  }
};

export const demoLogin = async (req, res) => {
  try {
    const { email, mobileNumber } = req.body;

    if (!email && !mobileNumber) {
      return res
        .status(400)
        .json({ error: "Email or mobile number is required." });
    }

    const student = await User.findOne({
      $or: [{ email }, { mobileNumber }],
      role: "demostudent",
    });

    if (!student) {
      return res.status(404).json({ error: "Demo student not found." });
    }

    res.status(200).json({
      message: "Demo login successful",
      data: student,
    });
  } catch (err) {
    console.error("Login error:", err.message);
    res.status(500).json({ error: err.message });
  }
};
