import DemoCourse from "../model/demoCoursesModel.js";
import uploadImageToCloudinary from "../utils/uploadImageToCloudinary.js";
import Review from "../model/demoCoursesReviewModel.js";
const cloudinaryFolder = "demo_classes/thumbnail";
// Create Demo Class
import mongoose from "mongoose";
import formatUserData from "../utils/formatInput.js";
import Teacher from "../model/teacherModel.js";

export const createDemoCourse = async (req, res) => {
  try {
    const formatData = formatUserData(req.body);
    const {
      subject,
      description,
      teachersId = [],
      category,
      scheduleAt,
      duration,
      requirements,
      syllabus,
      courseThumbnail,
      availableSeats,
      mode,
    } = formatData;

    if (!subject || !description) {
      return res.status(400).json({ error: "Missing required fields." });
    }

    // Validate teacher IDs
    if (teachersId.length > 0) {
      const validTeachers = await Teacher.find({ _id: { $in: teachersId } });
      if (validTeachers.length !== teachersId.length) {
        return res
          .status(400)
          .json({ error: "One or more teacher IDs are invalid." });
      }
    }

    // Upload image if needed
    let thumbnailUrl = courseThumbnail || null;
    const cloudinaryFolder = "demo-courses";
    if (courseThumbnail) {
      thumbnailUrl = await uploadImageToCloudinary(
        courseThumbnail,
        cloudinaryFolder
      );
    }

    // Create demo course
    const demoClass = new DemoCourse({
      subject,
      description,
      teachers: teachersId||[],
      category,
      scheduleAt,
      duration,
      requirements,
      syllabus,
      availableSeats,
      mode,
      courseThumbnail: thumbnailUrl,
    });

    // Save demo course
    const savedClass = await demoClass.save();

    // Add course to teachers
    // await Promise.all(
    //   teachersId.map(async (id) => {
    //     const teacher = await Teacher.findById(id);
    //     if (teacher) {
    //       teacher.assignedDemoCourses.push(savedClass._id);
    //       await teacher.save();
    //     }
    //   })
    // );

    res.status(201).json({
      message: "Demo class created successfully",
      data: savedClass,
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
};

export const addTeacherToDemoCourse = async (req, res) => {
  try {
    const { courseId, teacherIds = [] } = req.body;

    if (!courseId || teacherIds.length === 0) {
      return res.status(400).json({ error: "Missing courseId or teacherIds" });
    }

    // Validate course
    const course = await DemoCourse.findById(courseId);
    if (!course) {
      return res.status(404).json({ error: "Demo course not found." });
    }

    // Validate teacher IDs
    const validTeachers = await Teacher.find({ _id: { $in: teacherIds } });
    if (validTeachers.length !== teacherIds.length) {
      return res.status(400).json({ error: "One or more teacher IDs are invalid." });
    }

    // Update course assignedDemoCourses (avoid duplicates)
    teacherIds.forEach(id => {
      if (!course.teachers.includes(id)) {
        course.teachers.push(id);
      }
    });
    await course.save();

    // Update teachers to include this course (avoid duplicates)
    await Promise.all(
      teacherIds.map(async (id) => {
        const teacher = await Teacher.findById(id);
        if (teacher && !teacher.assignedDemoCourses.includes(courseId)) {
          teacher.assignedDemoCourses.push(courseId);
          await teacher.save();
        }
      })
    );

    res.status(200).json({ message: "Teachers added to demo course successfully", data: course });
  } catch (error) {
    console.log("error,",error.message)
    res.status(500).json({ error: error.message });
  }
};

// Get All
// we also add the mode
export const getAllDemoCourses = async (req, res) => {
  try {
    const { category, isActive } = req.query;
    let filter = {};

    if (category) {
      filter.category = category;
    }

    if (isActive === "true") {
      filter.isActive = true;
    } else if (isActive === "false") {
      filter.isActive = false;
    } else {
      filter.isActive = { $in: [true, false] };
    }

    const demoCourses = await DemoCourse.find(filter)
      .populate({
        path: "teachers",
        populate: {
          path: "user",
        },
      })
      .populate({
        path: "reviews",
        populate: {
          path: "student",
          select: "_id name",
        },
      });

    // If no courses are found
    if (!demoCourses || demoCourses.length === 0) {
      return res.status(404).json({ message: "No demo courses found" });
    }

    // Return the success response with the list of demo courses
    res.status(200).json({
      count: demoCourses.length,
      message: "Demo courses fetched successfully",
      demoCourses,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
};

// Update Demo Courses
export const updateDemoCourse = async (req, res) => {
  try {
    const { demoCourseId } = req.params;

    // Validate MongoDB ObjectId
    if (!mongoose.Types.ObjectId.isValid(demoCourseId)) {
      return res.status(400).json({ error: "Invalid demo course ID format." });
    }

    const formatData = formatUserData(req.body);

    const {
      subject,
      description,
      teacher,
      category,
      scheduleAt,
      duration,
      requirements,
      syllabus,
      courseThumbnail,
      availableSeats,
      bookedSeats,
      isActive,
    } = formatData;

    // Basic validation for required fields
    if (!subject || !category || !availableSeats) {
      return res.status(400).json({ message: "Missing required fields." });
    }

    if (typeof availableSeats !== "number" || availableSeats < 1) {
      return res.status(400).json({ message: "Invalid availableSeats value." });
    }

    // Check if the demo course exists
    const existingDemo = await DemoCourse.findById(demoCourseId);
    if (!existingDemo) {
      return res.status(404).json({ error: "Demo course not found." });
    }

    let updatedThumbnail = courseThumbnail;

    // Upload new thumbnail if provided
    if (courseThumbnail) {
      updatedThumbnail = await uploadImageToCloudinary(
        courseThumbnail,
        cloudinaryFolder
      );
    }

    // Prepare update fields
    const updateFields = {
      subject,
      description,
      teacher,
      category,
      scheduleAt,
      duration,
      requirements,
      syllabus,
      courseThumbnail: updatedThumbnail,
      availableSeats,
      bookedSeats,
      isActive,
    };

    const updatedDemoCourse = await DemoCourse.findByIdAndUpdate(
      demoCourseId,
      updateFields,
      { new: true, runValidators: true }
    );

    console.log(updatedDemoCourse);
    res.status(200).json({
      message: "Demo course updated successfully",
      demoCourse: updatedDemoCourse,
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
};

// Get Demo Courses
export const getDemoCoursesById = async (req, res) => {
  try {
    const { demoCourseId } = req.params;

    // Validate MongoDB ObjectId
    if (!mongoose.Types.ObjectId.isValid(demoCourseId)) {
      return res.status(400).json({ error: "Invalid course ID format." });
    }
    const demoClass = await DemoCourse.findById(demoCourseId)
      .populate({
        path: "teacher",
        select: "user",
        populate: {
          path: "user",
          select: "name", // only select name from user
        },
      })
      .populate({
        path: "reviews",
        populate: {
          path: "student",
          select: "_id name",
        },
      });

    if (!demoClass) {
      return res.status(404).json({ error: "Demo Course Not Found" });
    }
    res.status(200).json(demoClass);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

export const deleteDemoCourse = async (req, res) => {
  try {
    const { demoCourseId } = req.params;

    // Validate ObjectId
    if (!mongoose.Types.ObjectId.isValid(demoCourseId)) {
      return res.status(400).json({ error: "Invalid demo course ID format." });
    }

    // Find the course first
    const demoCourse = await DemoCourse.findById(demoCourseId);
    if (!demoCourse) {
      return res.status(404).json({ error: "Demo course not found." });
    }

    // Delete all associated reviews (if any)
    if (demoCourse.reviews?.length > 0) {
      await Review.deleteMany({ _id: { $in: demoCourse.reviews } });
    }

    // Delete the demo course
    await demoCourse.deleteOne();

    res.status(200).json({ message: "Demo course deleted successfully." });
  } catch (error) {
    console.error("Delete Demo Course Error:", error);
    res
      .status(500)
      .json({ error: "Internal server error", details: error.message });
  }
};

// Book a seat in a demo course
export const bookSeat = async (req, res) => {
  try {
    const { demoCourseId } = req.params;
    let studentData = req.student;

    // Validate ObjectId
    if (!mongoose.Types.ObjectId.isValid(demoCourseId)) {
      return res.status(400).json({
        success: false,
        error: "Invalid demo course ID.",
      });
    }

    // check that student is valid
    if (!studentData) {
      return res.status(404).json({
        success: false,
        error: "student not found.",
      });
    }

    // Check if seat is already booked by this student
    if (studentData.bookedSets.demoCourses.includes(demoCourseId)) {
      return res.status(400).json({
        success: false,
        error: "You have already booked a seat for this demo.",
      });
    }

    // Book the seat
    studentData.bookedSets.demoCourses.push(demoCourseId);
    await studentData.save();

    const demoCourse = await DemoCourse.findByIdAndUpdate(
      demoCourseId,
      {
        $inc: { availableSeats: -1, bookedSeats: 1 },
      },
      { new: true }
    );

    res.status(200).json({
      success: true,
      message: "Seat booked successfully",
    });
  } catch (error) {
    console.error("Error booking seat:", error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
};
