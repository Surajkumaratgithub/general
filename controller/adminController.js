import { sendPasswordToEmail } from "../middleware/sendPasswordToEmail.js";
import admin from "../model/adminModel.js";
import User from "../model/userModel.js";
import bcrypt from "bcrypt";

const SALT = Math.random(20);

export const createAdmin = async (req, res, next) => {
  const {name,email,mobileNumber,password,branch,mode}=req.body
  try {
    // console.log(req.body);
    const query = []
    if (email) {
      query.push({ email: email.trim().toLowerCase() });
    }
    if (mobileNumber) {
      query.push({ mobileNumber: mobileNumber?.trim()})
    }
    const existingUser = await User.findOne({$or:query});
    if (existingUser) {
      return res.status(400).json({ message:"User already exist with credintials" });
    }

    // const hashPass = await bcrypt.hash(password, SALT);    
    const user = await User.create({
      name:name,
      email: email,
      password: password,
      branch:branch,
      role: "admin",
      mode:mode
    });
    
    const result = await admin.create({ user: user._id });
    const sendMail = await sendPasswordToEmail({ ...req.body, role: "admin" });
    if (sendMail) {
      res
        .status(201)
        .json({
          message: "Admin created successfuly,Email send to admin mail Id",
          result,
          success: true,
        });
    }
  } catch (error) {
    console.log("Error occured while creating admin ", error.message);
    error.statusCode = 500;
    next(error);
  }
};

export const createSuperAdmin = async (req, res, next) => {
  const {name,email,mobileNumber,password}=req.body
  try {
    // console.log(req.body);
    const query = []
    if (email) {
      query.push({ email: email.trim().toLowerCase() });
    }
    if (mobileNumber) {
      query.push({ mobileNumber: mobileNumber?.trim()})
    }
    const existingUser = await User.findOne({$or:query});
    if (existingUser) {
      return res.status(400).json({ message:"User already exist with credintials" });
    }

    // const hashPass = await bcrypt.hash(password, SALT);    
    const user = await User.create({
      name:name,
      email: email,
      password: password,
      branch:branch,
      role: "superadmin",
      mode:mode
    });
    
    const result = await admin.create({ user: user._id });
    const sendMail = await sendPasswordToEmail({ ...req.body, role: "superadmin" });
    if (sendMail) {
      res
        .status(201)
        .json({
          message: "superAdmin created successfuly,Email send to superadmin mail Id",
          result,
          success: true,
        });
    }
  } catch (error) {
    console.log("Error occured while creating admin ", error.message);
    error.statusCode = 500;
    next(error);
  }
};

