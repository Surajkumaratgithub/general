// controllers/loginController.js
import bcrypt from "bcryptjs";
import User from "../model/userModel.js";
import Student from "../model/studentModel.js";
import jwt from "jsonwebtoken";
import Otp from "../model/otpModel.js";
import crypto from "crypto";
import formatUserData from "../utils/formatInput.js";
import { transporter } from "../utils/emailTransporter.js";

const getCookieOptions = (req) => {
  const isSecure = req.secure || req.headers["x-forwarded-proto"] === "https";
  const sameSite = isSecure ? "none" : "lax";

  return {
    httpOnly: true,
    secure: isSecure,
    sameSite,
    expires: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000),
  };
};
// Helper function to send OTP via email
const sendOtpEmail = async (email, otp) => {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Your Login OTP",
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2>Login Verification</h2>
        <p>Your One-Time Password (OTP) for login is:</p>
        <h1 style="font-size: 32px; background-color: #f0f0f0; padding: 10px; text-align: center; letter-spacing: 5px;">${otp}</h1>
        <p>This OTP is valid for 10 minutes.</p>
        <p>If you did not request this OTP, please ignore this email.</p>
      </div>
    `,
  };

  return transporter.sendMail(mailOptions);
};

export const login = async (req, res) => {
  try {
    const { email, mobileNumber, password } = req.body;

    if ((!email && !mobileNumber) || !password?.trim()) {
      return res.status(400).json({
        error: "Email or mobile number and password are required",
      });
    }

    const normalizedEmail = email?.trim().toLowerCase();

    // Find user or student
    let [user, student] = [null, null];
    if (normalizedEmail) {
      [user, student] = await Promise.all([
        User.findOne({ email: normalizedEmail }),
        Student.findOne({ email: normalizedEmail }),
      ]);
    } else if (mobileNumber) {
      [user, student] = await Promise.all([
        User.findOne({ mobileNumber }),
        Student.findOne({ mobileNumber }),
      ]);
    }

    const account = user || student;
    if (!account) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, account.password);
    if (!isPasswordValid) {
      return res.status(400).json({
        message: "Invalid password",
      });
    }

    if (!normalizedEmail) {
      return res.status(400).json({
        message: "Email is required to generate OTP",
      });
    }

    // Generate OTP
    const otpCode = crypto.randomInt(100000, 999999).toString();
    const otpHash = await bcrypt.hash(otpCode, 10);

    // Remove any existing OTP for this email
    await Otp.findOneAndDelete({ email: normalizedEmail });

    // Save new OTP with expiration 10 minutes
    await Otp.create({
      email: normalizedEmail,
      otp: otpHash,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000),
    });

    // Console.log OTP for now
    console.log("Generated OTP:", otpCode);

    return res.status(200).json({
      success: true,
      message: "Password verified. OTP sent to your email address.",
      requiresOtp: true,
    });
  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).json({
      message: "Server error",
      error: error.message,
    });
  }
};

// OTP-based login - Step 2: Verify OTP
export const verifyOtp = async (req, res) => {
  try {
    const { email, otp } = formatUserData(req.body);
    const normalizedEmail = email.trim().toLowerCase();

    // Find OTP record
    const record = await Otp.findOne({ email: normalizedEmail });
    if (!record) {
      return res.status(404).json({
        message: "OTP record not found",
      });
    }

    // Check if OTP expired
    if (record.expiresAt < Date.now()) {
      await Otp.deleteOne({ email: normalizedEmail });
      return res.status(400).json({
        message: "OTP has expired",
      });
    }

    // Verify OTP
    const isOtpValid = await bcrypt.compare(otp, record.otp);
    if (!isOtpValid) {
      return res.status(401).json({
        message: "Invalid OTP",
      });
    }

    // OTP is valid, delete it
    await Otp.deleteOne({ email: normalizedEmail });

    // Find user or student
    const [user, student] = await Promise.all([
      User.findOne({ email: normalizedEmail }),
      Student.findOne({ email: normalizedEmail }),
    ]);

    const account = user || student;
    if (!account) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // Generate token
    const tokenPayload = {
      id: account._id,
      email: account.email,
      role: user ? user.role : "student",
    };

    const token = jwt.sign(tokenPayload, process.env.JWT_SECRET, {
      expiresIn: tokenPayload.role === "student" ? "12h" : "3h",
    });

    // Prepare response data
    const responseData = {
      id: account._id,
      name: account.name,
      email: account.email,
      role: tokenPayload.role,
    };

    return res
      .cookie("token", token, getCookieOptions(req))
      .status(200)
      .json({
        success: true,
        message: `${tokenPayload.role} login successful`,
        token,
        user: responseData,
      });
  } catch (error) {
    console.error("OTP Verification Error:", error);
    res.status(500).json({
      message: "Server error",
      error: error.message,
    });
  }
};

// Resend OTP
export const resendOtp = async (req, res) => {
  try {
    const { email } = req.body;
    const normalizedEmail = email?.trim().toLowerCase();

    if (!normalizedEmail) {
      return res.status(400).json({
        success: false,
        message: "Email is required",
      });
    }

    // Check if user exists
    const [user, student] = await Promise.all([
      User.findOne({ email: normalizedEmail }),
      Student.findOne({ email: normalizedEmail }),
    ]);

    if (!user && !student) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // Generate new OTP
    const otp = crypto.randomInt(100000, 999999).toString();
    const otpHash = await bcrypt.hash(otp, 10);

    await Otp.findOneAndDelete({ email: normalizedEmail });
    await Otp.create({
      email: normalizedEmail,
      otp: otpHash,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
    });

    // Send OTP email
    //await sendOtpEmail(normalizedEmail, otp);
    console.log("otp is",otp);
    return res.status(200).json({
      success: true,
      message: "OTP resent to your email address",
    });
  } catch (error) {
    console.error("Resend OTP Error:", error);
    res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message,
    });
  }
};

// Password change
export const changePassword = async (req, res) => {
  try {
    const { email, oldPassword, newPassword } = req.body;

    if (!email || !oldPassword || !newPassword) {
      return res.status(400).json({
        message: "All fields are required",
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    // Find user or student
    const [user, student] = await Promise.all([
      User.findOne({ email: normalizedEmail }),
      Student.findOne({ email: normalizedEmail }),
    ]);

    const account = user || student;
    if (!account) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    // Verify old password
    const isMatch = await bcrypt.compare(oldPassword, account.password);
    if (!isMatch) {
      return res.status(400).json({
        message: "Old password is incorrect",
      });
    }

    // Update password
    account.password = newPassword;
    await account.save();

    return res.status(200).json({
      success: true,
      message: "Password changed successfully",
    });
  } catch (error) {
    console.error("Change Password Error:", error);
    res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message,
    });
  }
};

// Forgot password - request reset token
export const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        message: "Email is required",
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    // Find user or student
    const [user, student] = await Promise.all([
      User.findOne({ email: normalizedEmail }),
      Student.findOne({ email: normalizedEmail }),
    ]);

    const account = user || student;
    if (!account) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    // Generate reset token
    const resetToken = jwt.sign(
      {
        id: account._id,
        role: user ? user.role : "student",
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.status(200).json({
      success: true,
      message: "Reset token generated",
      resetToken,
    });
  } catch (error) {
    console.error("Forgot Password Error:", error);
    res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message,
    });
  }
};

// Reset password with token
export const resetPassword = async (req, res) => {
  try {
    const { resetToken, newPassword } = req.body;

    if (!resetToken || !newPassword) {
      return res.status(400).json({
        message: "Reset token and new password are required",
      });
    }

    // Verify token
    const decoded = jwt.verify(resetToken, process.env.JWT_SECRET);
    const { id, role } = decoded;

    if (!id || !role) {
      return res.status(400).json({
        message: "Invalid token payload",
      });
    }

    // Find account
    const account =
      role === "student" ? await Student.findById(id) : await User.findById(id);

    if (!account) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    // Update password
    account.password = newPassword;
    await account.save();

    const capitalizedRole = role.charAt(0).toUpperCase() + role.slice(1);
    return res.status(200).json({
      success: true,
      message: `${capitalizedRole} password has been reset successfully`,
    });
  } catch (error) {
    console.error("Reset Password Error:", error);
    return res.status(400).json({
      success: false,
      message: "Invalid or expired token",
      error: error.message,
    });
  }
};

// Logout
export const logout = (req, res) => {
  res.clearCookie("token", getCookieOptions(req));
  return res.status(200).json({
    success: true,
    message: "Logged out successfully",
  });
};
