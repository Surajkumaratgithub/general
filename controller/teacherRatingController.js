import TeacherRating from "../model/teaches/teacherRating.js";
import mongoose from "mongoose";

// Create a new rating
export const createRating = async (req, res) => {
  try {
    const { teacherId, rating, comment } = req.body;
    const studentId = req.student?._id; // come from middleware
    if (!teacherId || !rating) {
      return res
        .status(400)
        .json({ message: "Teacher ID and rating are required" });
    }

    const newRating = await TeacherRating.create({
      teacherId,
      studentId,
      rating,
      comment,
    });

    res
      .status(201)
      .json({ message: "Rating submitted successfully", data: newRating });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

// Get all ratings for a teacher
export const getRatingsForTeacher = async (req, res) => {
  try {
    const { teacherId } = req.params;

    const ratings = await TeacherRating.find({ teacherId })
      .populate({
        path: "teacherId",
        populate: {
          path: "user",
          select: "name", // Adjust based on your User schema
        },
        select: "user",
      })
      .populate("studentId", "name")
      .sort({ createdAt: -1 });

    res.status(200).json({ data: ratings });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

// Get average rating for a teacher
export const getAverageRating = async (req, res) => {
  try {
    const { teacherId } = req.params;

    const result = await TeacherRating.aggregate([
      { $match: { teacherId: new mongoose.Types.ObjectId(teacherId) } },
      {
        $group: {
          _id: "$teacherId",
          averageRating: { $avg: "$rating" },
          totalRatings: { $sum: 1 },
        },
      },
    ]);

    if (result.length === 0) {
      return res
        .status(404)
        .json({ message: "No ratings found for this teacher" });
    }

    res.status(200).json(result[0]);
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
};
