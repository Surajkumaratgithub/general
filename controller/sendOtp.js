import nodemailer from "nodemailer";
import dotenv from "dotenv";
import crypto from "crypto";
import Otp from "../model/otpModel.js";
import bcrypt from "bcryptjs";

const generateOtp = () => {
  const otp = crypto.randomInt(100000, 999999); // from 100000 to 999999
  return otp.toString();
};

// Hash OTP using bcrypt
const genHashOtp = async (otp) => {
  const salt = await bcrypt.genSalt(10);
  return await bcrypt.hash(otp, salt); // Hash the OTP with salt
};

dotenv.config();

export const sendOtp = async (req, res) => {
  try {
    // Assuming req.user is set after successful registration in the controller
    const { email, name } = req.body;

    if (!email || !email.trim()) {
      return res.status(400).json({ message: "Name and email are required" });
    }

    const otp = generateOtp();
    console.log(otp);
    const hashOtp = await genHashOtp(otp); // Generate OTP

    // Check if email exists in the database
    const existingOtp = await Otp.findOne({ email: email.trim() });
    if (existingOtp) {
      await Otp.deleteOne({ email });
    }

    const fullName =
      name?.firstName && name?.lastName
        ? `${name.firstName} ${name.lastName}`
        : "";

    // Save the new OTP in the database
    const otpDocument = new Otp({
      email,
      otp: hashOtp, // Save hashed OTP
      expiresAt: Date.now() + 2 * 60 * 1000, // OTP valid for 2 minutes
    });

    await otpDocument.save();

    // Set up the email transporter
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: process.env.EMAIL_PORT,
      secure: false,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD,
      },
      tls: {
        rejectUnauthorized: false,
      },
    });

    console.log("transport start");
    // Verify transporter connection
    await transporter.verify();

    // HTML email template
    const htmlContent = `<!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
      <title>Email Verification</title>
      <style>
        body {
          font-family: "Segoe UI", sans-serif;
          background-color: #f4f6f8;
          margin: 0;
          padding: 0;
          color: #333;
        }
        .container {
          max-width: 600px;
          margin: 40px auto;
          background-color: #ffffff;
          border-radius: 10px;
          box-shadow: 0 5px 20px rgba(0,0,0,0.05);
          overflow: hidden;
        }
        .header {
          background-color: #1E88E5;
          color: #fff;
          text-align: center;
          padding: 30px 20px;
        }
        .header h1 {
          margin: 0;
          font-size: 26px;
        }
        .content {
          padding: 30px 25px;
        }
        .content h2 {
          font-size: 22px;
          margin-bottom: 10px;
          color: #222;
        }
        .content p {
          font-size: 16px;
          line-height: 1.7;
          margin-bottom: 16px;
          color: #555;
        }
        .otp-box {
          font-size: 28px;
          font-weight: bold;
          letter-spacing: 6px;
          background-color: #f0f4ff;
          color: #1E88E5;
          padding: 15px 20px;
          border-radius: 8px;
          text-align: center;
          width: fit-content;
          margin: 25px auto;
        }
        .footer {
          text-align: center;
          font-size: 12px;
          padding: 20px;
          background-color: #f4f4f4;
          color: #999;
        }
        .footer a {
          color: #1E88E5;
          text-decoration: none;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>Verify Your Email Address</h1>
        </div>
        <div class="content">
          <h2>Hello ${fullName},</h2>
          <p>Thank you for registering with <strong>Weseeder Learning</strong>! To continue, please use the One-Time Password (OTP) below to verify your email address:</p>
    
          <div class="otp-box">${otp}</div>
    
          <p>This OTP is valid for the next <strong>10 minutes</strong>. Please do not share it with anyone.</p>
          <p>If you didn't request this, you can safely ignore this email. We're here to help if you need anything!</p>
          <p>— The Horizon Team</p>
        </div>
        <div class="footer">
          <p>© 2025 Weseeder Learning. All rights reserved.</p>
          <p><a href="http://localhost:3000/unsubscribe">Unsubscribe</a></p>
        </div>
      </div>
    </body>
    </html>
    `;

    // Email options
    const mailOptions = {
      from: `"Horizon Institute" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Welcome to Horizon Institute – Thank You for Trusting Us!",
      html: htmlContent,
    };

    // Send the email
    await transporter.sendMail(mailOptions);
    console.log("email sent");
    // Send success response
    return res.status(200).json({
      message: "OTP sent successfully to your email.",
      email: email,
    });
  } catch (error) {
    console.error("Error sending welcome email:", error);
  }
};
