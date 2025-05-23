// import jwt from "jsonwebtoken";
// import bcrypt from "bcrypt";
// import User from "../model/userModel.js";
// import formatUserData from "../utils/formatInput.js";
// import { createToken } from "../utils/generateToken.js";
// // import Teacher from "../model/teacherModel.js";
// // import admin from "../model/adminModel.js";

// // export const register = async (req, res, next) => {
// //   try {
// //     const formatData = formatUserData(req.body);
// //     const { email, ...rest } = formatData;
// //     if (!email) {
// //       return res.status(400).json({ message: "Email is required" });
// //     }

// //     const existingUser = await User.findOne({
// //       email: email.trim().toLowerCase(),
// //     });
// //     if (existingUser) {
// //       return res.status(400).json({ message: "Email already in use" });
// //     }
// //     const newUser = await User.create({
// //       email: email.trim().toLowerCase(),
// //       ...rest,
// //     });

// //     const token = createToken(newUser);

// //     req.user = { id: newUser._id, email: newUser.email, name: newUser.name }; // Optional: attach minimal info

// //     res.status(201).json({
// //       success: true,
// //       message: "User registered successfully",
// //       token,
// //       user: {
// //         _id: newUser._id,
// //         name: newUser.name,
// //         email: newUser.email,
// //         role: newUser.role||"user",
// //       },
// //     });

// //     next(); // For chaining email send etc.
// //   } catch (error) {
// //     console.error("Register Error:", error);
// //     res.status(500).json({ message: "Server error", error: error.message });
// //   }
// // };

// // {
// //   "email": "john.doe@example.com",
// //   "password": "Password123"
// // }

// // login user
// // export const login = async (req, res) => {
// //   try {
// //     const { email, password } = req.body;

// //     if (!email || !password) {
// //       return res
// //         .status(400)
// //         .json({ message: "Email and password are required" });
// //     }

// //     const user = await User.findOne({ email: email.trim().toLowerCase() });
// //     if (!user) {
// //       return res.status(400).json({ message: "Invalid credentials" });
// //     }
// //     const isMatch = await bcrypt.compare(password, user.password);

// //     if (!isMatch) {
// //       return res.status(400).json({ message: "Invalid credentials" });
// //     }
// //     let dataAccordingToRole;
// //     if (user.role ==='teacher') {
// //      dataAccordingToRole=await Teacher.findOne({user:user._id}).populate('user')
// //     }
// //     else if (user.role ==="admin") {
// //     dataAccordingToRole =  admin.findOne({user:user._id}).populate('user')
// //     }
// //     const token = createToken(user);

// //     res.status(200).json({
// //       success: true,
// //       message: "Login successful",
// //       token,
// //       user:dataAccordingToRole,
// //     });
// //   } catch (error) {
// //     console.error("Login Error:", error);
// //     res.status(500).json({ message: "Server error", error: error.message });
// //   }
// // };

// // update user

// // { note --- jo change ho ti hai usko pass kro
// //   "firstName": "   john   ",
// //   "lastName": "  doe  ",
// //   "dob": "25/12/1990",
// //   "age": "34",
// //   "email": "john.doe@example.com",
// //   "mobileNumber": "1234567890",
// // }

// export const updateUser = async (req, res) => {
//   try {
//     const { id } = req.params;
//     const updateData = req.body;
//     const formattedData = formatUserData(updateData);

//     const user = await User.findByIdAndUpdate(id, formattedData, { new: true });
//     if (!user) return res.status(404).json({ message: "User not found" });

//     res.status(200).json({ success: true, user });
//   } catch (error) {
//     res.status(500).json({ message: error.message });
//   }
// };

// //get user controller *********************************************

// // get user by id

// // {
// //   "id": "67d91268e3b79d854913b166"
// // }

// export const getUserById = async (req, res) => {
//   try {
//     const { id } = req.params;
//     const user = await User.findById(id).select("-password"); // Exclude password
//     if (!user) return res.status(404).json({ message: "User not found" });

//     res.status(200).json({ success: true, user });
//   } catch (error) {
//     res.status(500).json({ message: error.message });
//   }
// };

// // get all users
// export const getAllUsers = async (req, res) => {
//   try {
//     const users = await User.find().select("-password"); // Exclude password
//     res.status(200).json({ success: true, users });
//   } catch (error) {
//     res.status(500).json({ message: error.message });
//   }
// };
