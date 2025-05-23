import AssignmentSubmission from "../model/courses/AssignmentSubmission.js";
import uploadToTeams from "../utils/uploadVideoToTeams.js";

export const submitAssignment = async (req, res) => {
  try {
    const { assignmentId } = req.params;
    const studentId = req.user.id;

    if (!req.file) {
      return res.status(400).json({ message: "Video file is required." });
    }
    console.log("req.file is:",req.file);

    const existingSubmission = await AssignmentSubmission.findOne({
      assignmentId,
      studentId,
    });

    if (existingSubmission) {
      return res.status(400).json({ message: "Assignment already submitted." });
    }

    const videoBuffer = req.file.buffer;
    const originalName = req.file.originalname;
    const videoUrl = await uploadToTeams(videoBuffer, originalName);

    const submission = new AssignmentSubmission({
      assignmentId,
      studentId,
      submittedFile: videoUrl,
    });

    await submission.save();

    res.status(201).json({
      message: "Assignment submitted successfully",
      submission,
    });
  } catch (error) {
    console.error("Submit Assignment Error:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

// Get all submissions
export const getSubmissionsByAssignment = async (req, res) => {
  try {
    const { assignmentId } = req.params;

    const submissions = await AssignmentSubmission.find({ assignmentId })
      .populate("studentId", "name email")
      .populate("evaluatedBy", "name email");

    res.status(200).json(submissions);
  } catch (error) {
    console.error("Get Submissions Error:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

// Get a specific submission by student
export const getStudentSubmission = async (req, res) => {
  try {
    const { assignmentId, studentId } = req.params;

    if (!assignmentId || !studentId) {
      return res
        .status(400)
        .json({ message: "Assignment ID and Student ID are required." });
    }

    const submission = await AssignmentSubmission.findOne({
      assignmentId,
      studentId,
    });

    if (!submission) {
      return res.status(404).json({ message: "Submission not found." });
    }

    res.status(200).json({ submission });
  } catch (error) {
    console.error("Get Student Submission Error:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

// Evaluate a submission (Teacher)
export const evaluateSubmission = async (req, res) => {
  try {
    const { submissionId } = req.params;
    const { feedback, rate } = req.body;
    const evaluatedBy = req.user.id;

    const submission = await AssignmentSubmission.findById(submissionId);

    if (!submission) {
      return res.status(404).json({ message: "Submission not found" });
    }

    submission.feedback = feedback;
    submission.rate = rate;
    submission.evaluatedBy = evaluatedBy;
    submission.evaluatedAt = new Date();

    await submission.save();

    res.status(200).json({ message: "Submission evaluated", submission });
  } catch (error) {
    console.error("Evaluate Submission Error:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};
