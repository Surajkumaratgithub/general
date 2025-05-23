// controllers/sessionController.js
import Session from "../model/courses/Session.js";
// import Course from "../model/courses/courseModel.js";
// import Class from "../model/courses/Class.js";
import mongoose from "mongoose";

// Create session
export const createSession = async (req, res) => {
  try {
    const { courseId, title, description, startDate, endDate } = req.body;

    if (!mongoose.Types.ObjectId.isValid(courseId)) {
      return res.status(400).json({ error: "Invalid course ID." });
    }

    const session = new Session({
      course: courseId,
      title,
      description,
      startDate,
      endDate,
    });

    await session.save();
    res.status(201).json({ message: "Session created", session });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Get all sessions of a course
export const getSessionsByCourse = async (req, res) => {
  try {
    const { courseId } = req.params;
    const sessions = await Session.find({ course: courseId });
    res.status(200).json({ sessions });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Get a single session
export const getSessionById = async (req, res) => {
  try {
    const session = await Session.findById(req.params.sessionId);
    if (!session) return res.status(404).json({ error: "Session not found" });
    res.status(200).json(session);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Update session
export const updateSession = async (req, res) => {
  try {
    const { sessionId } = req.params;
    const updates = req.body;
    const updatedSession = await Session.findByIdAndUpdate(sessionId, updates, {
      new: true,
      runValidators: true,
    });
    res.status(200).json({ message: "Session updated", session:updatedSession });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Delete session
export const deleteSession = async (req, res) => {
  try {
    const session = await Session.findById(req.params.sessionId);
    if (!session) return res.status(404).json({ error: "Session not found" });

    await session.remove(); // triggers cascade delete of classes
    res.status(200).json({ message: "Session deleted" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};
