import DemoCourse from "../model/demoCoursesModel.js";
import Review from "../model/demoCoursesReviewModel.js";
import mongoose from "mongoose";
import formatUserData from "../utils/formatInput.js";
export const createReview = async (req, res) => {
  try {
    const formatData = formatUserData(req.body);
    const { rating, comment } = formatData || {};
    const studentId = req.user.id;
    const demoCourseId = req.params.demoCourseId;

    // Validate ObjectId
    if (!mongoose.Types.ObjectId.isValid(demoCourseId)) {
      return res.status(400).json({ error: "Invalid demo course ID." });
    }

    // Basic validation
    if (!rating || !comment) {
      return res
        .status(400)
        .json({ error: "Rating and comment are required." });
    }

    // Check if demo course exists
    const demoCourse = await DemoCourse.findById(demoCourseId);
    if (!demoCourse) {
      return res.status(404).json({ error: "Demo course not found." });
    }

    // Check if student has already reviewed this course
    const existingReview = await Review.findOne({
      user: studentId,
      course: demoCourseId, // only if you're linking reviews to a course
    });
    if (existingReview) {
      return res
        .status(400)
        .json({ error: "You have already reviewed this class." });
    }

    // Create and save new review
    const newReview = new Review({
      rating,
      comment,
      student: studentId,
      course: demoCourseId, // assuming your Review schema has a `course` field
    });

    const savedReview = await newReview.save();

    // Add review to demo course
    demoCourse.reviews.push(savedReview._id);
    await demoCourse.save();

    res.status(201).json({
      message: "Review created successfully.",
      reviewId: savedReview._id,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};
// Update a review
export const updateReview = async (req, res) => {
  try {
    const { rating, comment } = req.body;
    const { reviewId } = req.params;
    const demoCourseId = req.params.demoCourseId;
    const studentId = req.user._id;

    // Find the review by its ID
    const review = await Review.findById(reviewId);

    if (!review) {
      return res.status(404).json({
        success: false,
        message: "Review not found",
      });
    }

    // Check if the student is the one who created the review
    if (review.student.toString() !== studentId.toString()) {
      return res.status(403).json({
        success: false,
        message: "You are not authorized to update this review",
      });
    }

    // Update the review fields
    if (typeof rating !== "undefined") review.rating = rating;
    if (typeof comment !== "undefined") review.comment = comment;

    // Save the updated review
    await review.save();

    // Optional: ensure the review is still linked to the course
    const demoCourse = await DemoCourse.findById(demoCourseId);
    if (!demoCourse) {
      return res.status(404).json({
        success: false,
        message: "Associated course not found",
      });
    }

    // Save the demo course
    await demoCourse.save();

    // Respond with success
    return res.status(200).json({
      success: true,
      message: "Review updated successfully and synced with demo course",
    });
  } catch (error) {
    console.error("Error updating review:", error);
    return res.status(500).json({
      success: false,
      message: "Something went wrong while updating the review",
      error: error.message,
    });
  }
};

export const getReview = async (req, res) => {
  try {
    const { reviewId } = req.params;

    // Find the review by its ID and populate the user (student)
    const review = await Review.findById(reviewId).populate({
      path: "student",
      select: "_id name",
    });

    if (!review) {
      return res.status(404).json({
        success: false,
        message: "Review not found",
      });
    }
    // Return the review data
    return res.status(200).json({
      success: true,
      message: "Review fetched successfully",
      data: review,
    });
  } catch (error) {
    console.error("Error fetching review:", error);
    return res.status(500).json({
      success: false,
      message: "Something went wrong",
      error: error.message,
    });
  }
};

// Delete a review
export const deleteReview = async (req, res) => {
  try {
    const { reviewId } = req.params;
    const demoCourseId = req.params.demoCourseId;
    const studentId = req.user._id;

    // Find the review by its ID
    const review = await Review.findById(reviewId);

    if (!review) {
      return res.status(404).json({
        success: false,
        message: "Review not found",
      });
    }

    // Check if the review belongs to the current student
    const isOwner = review.student.toString() === studentId.toString();

    if (!isOwner) {
      return res.status(403).json({
        success: false,
        message: "You are not authorized to delete this review",
      });
    }

    // Remove the review from the DemoCourse
    await DemoCourse.findByIdAndUpdate(
      demoCourseId,
      { $pull: { reviews: review._id } },
      { new: true }
    );

    // Delete the review
    await review.deleteOne();

    return res.status(200).json({
      success: true,
      message: "Review deleted successfully",
    });
  } catch (error) {
    console.error("Error deleting review:", error);
    return res.status(500).json({
      success: false,
      message: "Something went wrong while deleting the review",
      error: error.message,
    });
  }
};
