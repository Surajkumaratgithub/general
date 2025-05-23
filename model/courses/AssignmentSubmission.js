import mongoose from "mongoose";

const assignmentSubmissionSchema = new mongoose.Schema(
  {
    assignmentId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Assignment",
      required: true,
    },
    studentId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Student",
      required: true,
    },
    submittedFile: {
      type: String, // URL of video
      required: true,
    },
    submittedAt: {
      type: Date,
      default: Date.now,
    },

    // Teacher's evaluation
    feedback: String,
    rate: {
      type: Number,
      min: 0,
      max: 5,
      required: true,
    },
    evaluatedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Teacher",
    },
    evaluatedAt: {
      type: Date,
      validate: {
        validator: function (v) {
          return this.feedback || this.rate === undefined || v !== undefined;
        },
        message:
          "Evaluation date must be set only when feedback and rate are provided.",
      },
    },
  },
  { timestamps: true }
);

const AssignmentSubmission = mongoose.model(
  "AssignmentSubmission",
  assignmentSubmissionSchema
);

export default AssignmentSubmission;
