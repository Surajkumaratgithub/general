// controllers/classController.js
import Class from "../model/courses/Class.js";
// import Session from "../model/courses/Session.js";
import mongoose from "mongoose";

// Create class
export const createClass = async (req, res) => {
  try {
    const { sessionId, topic, scheduledDate, durationMinutes, resources } = req.body;

    if (!mongoose.Types.ObjectId.isValid(sessionId)) {
      return res.status(400).json({ error: "Invalid session ID" });
    }

    const newClass = new Class({
      session: sessionId,
      topic,
      scheduledDate,
      durationMinutes,
      resources,
    });

    await newClass.save();
    res.status(201).json({ message: "Class created", newClass });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Get all classes by session
export const getClassesBySession = async (req, res) => {
  try {
    const classes = await Class.find({ session: req.params.sessionId });
    res.status(200).json({ classes });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Get class by ID
export const getClassById = async (req, res) => {
  try {
    const classObj = await Class.findById(req.params.classId);
    if (!classObj) return res.status(404).json({ error: "Class not found" });
    res.status(200).json(classObj);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Update class
export const updateClass = async (req, res) => {
  try {
    const updated = await Class.findByIdAndUpdate(req.params.classId, req.body, {
      new: true,
      runValidators: true,
    });
    res.status(200).json({ message: "Class updated", updated });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Delete class
export const deleteClass = async (req, res) => {
  try {
    const classToDelete = await Class.findByIdAndDelete(req.params.classId);
    if (!classToDelete) return res.status(404).json({ error: "Class not found" });
    res.status(200).json({ message: "Class deleted" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};
