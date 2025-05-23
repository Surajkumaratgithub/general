import Assignment from "../model/teaches/Assignment.js";
import mongoose from "mongoose";
// we need to make the if status is public then only dueDate is set

// In drafts do not set due Date
// Create a new assignment
export const createAssignment = async (req, res) => {
  try {
    let { title, description, dueDate, status } = req.body;
    const { courseId } = req.params;

    if (!title || !description || !courseId) {
      return res.status(400).json({
        success: false,
        message: "Fields (title, description, status, courseId) are required.",
      });
    }

    let deadlineStatus = "draft";
    // Check dueDate only for published the assignment
    if (status === "public") {
      if (!dueDate) {
        return res.status(400).json({
          success: false,
          message: "Due date is required for public assignments.",
        });
      }

      const parsedDueDate = new Date(dueDate);
      if (isNaN(parsedDueDate.getTime()) || parsedDueDate <= new Date()) {
        return res.status(400).json({
          success: false,
          message:
            "Due date must be a valid future date for public assignments.",
        });
      }

      deadlineStatus = "active";
    } else {
      dueDate = undefined;
    }

    const newAssignment = new Assignment({
      title,
      description,
      dueDate,
      course: courseId,
      status,
      deadlineStatus,
      teacher: req.teacherId, // from auth middleware
    });

    await newAssignment.save();

    res.status(201).json({
      success: true,
      message: "Assignment created successfully",
      assignment: newAssignment,
    });
  } catch (error) {
    console.error("Assignment creation failed:", error);
    res.status(500).json({
      success: false,
      message: "Server error while creating assignment.",
    });
  }
};

export const updateAssignment = async (req, res) => {
  try {
    const { assignmentId } = req.params;
    let { title, description, dueDate, status } = req.body;

    if (!title || !description || !status) {
      return res.status(400).json({
        success: false,
        message: "Fields (title, description, status) are required.",
      });
    }

    const assignment = await Assignment.findById(assignmentId);
    if (!assignment) {
      return res.status(404).json({
        success: false,
        message: "Assignment not found.",
      });
    }

    let deadlineStatus = "draft";

    if (status === "public") {
      if (!dueDate) {
        return res.status(400).json({
          success: false,
          message: "Due date is required for public assignments.",
        });
      }

      const parsedDueDate = new Date(dueDate);
      if (isNaN(parsedDueDate.getTime()) || parsedDueDate <= new Date()) {
        return res.status(400).json({
          success: false,
          message:
            "Due date must be a valid future date for public assignments.",
        });
      }

      assignment.dueDate = parsedDueDate;
      deadlineStatus = "active";
    } else {
      assignment.dueDate = undefined;
    }

    // Update fields
    assignment.title = title;
    assignment.description = description;
    assignment.status = status;
    assignment.deadlineStatus = deadlineStatus;

    await assignment.save();

    res.status(200).json({
      success: true,
      message: "Assignment updated successfully",
      assignment,
    });
  } catch (error) {
    console.error("Assignment update failed:", error);
    res.status(500).json({
      success: false,
      message: "Server error while updating assignment.",
    });
  }
};

export const getAssignmentsByCourse = async (req, res) => {
  try {
    const { courseId } = req.params;
    const { status, deadlineStatus } = req.query;

    // Validate courseId
    if (!courseId || !mongoose.Types.ObjectId.isValid(courseId)) {
      return res.status(400).json({
        success: false,
        message: "A valid courseId is required.",
      });
    }

    // Build dynamic filter object
    const filter = { course: courseId };

    if (status && ["draft", "public"].includes(status)) {
      filter.status = status;
    }

    if (
      deadlineStatus &&
      ["active", "expired", "draft"].includes(deadlineStatus)
    ) {
      filter.deadlineStatus = deadlineStatus;
    }

    const assignments = await Assignment.find(filter).populate({
      path: "teacher",
      select: "name user",
      populate: {
        path: "user",
        select: "name",
      },
    });

    if (!assignments.length) {
      return res.status(404).json({
        success: false,
        message: "No assignments found for this course.",
      });
    }

    res.status(200).json({
      success: true,
      count: assignments.length,
      message: "Assignments fetched successfully.",
      assignments,
    });
  } catch (error) {
    console.error("Error fetching assignments:", error);
    res.status(500).json({
      success: false,
      message: "Server error while fetching assignments.",
    });
  }
};

export const getAssignmentById = async (req, res) => {
  try {
    const { assignmentId } = req.params;

    if (!assignmentId) {
      return res.status(400).json({
        success: false,
        message: "Assignment ID is required.",
      });
    }

    const assignment = await Assignment.findById(assignmentId).populate({
      path: "teacher",
      select: "name user",
      populate: {
        path: "user",
        select: "name",
      },
    });

    if (!assignment) {
      return res.status(404).json({
        success: false,
        message: "Assignment not found.",
      });
    }

    res.status(200).json({
      success: true,
      message: "Assignment fetched successfully.",
      assignment,
    });
  } catch (error) {
    console.error("Error fetching assignment:", error);
    res.status(500).json({
      success: false,
      message: "Server error while fetching the assignment.",
    });
  }
};

// Need to work also delete the student submission with the assignment delete.
export const deleteAssignment = async (req, res) => {
  try {
    const { assignmentId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(assignmentId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid assignment ID format.",
      });
    }

    const assignment = await Assignment.findByIdAndDelete(assignmentId);

    if (!assignment) {
      return res.status(404).json({
        success: false,
        message: "Assignment not found.",
      });
    }

    res.status(200).json({
      success: true,
      message: "Assignment deleted successfully.",
    });
  } catch (error) {
    console.error("Error deleting assignment:", error);
    res.status(500).json({
      success: false,
      message: "Server error while deleting assignment.",
    });
  }
};
