const mongoose = require("mongoose");

const TeacherDashboardSchema = new mongoose.Schema(
  {
    teacherId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Teacher",
      required: true,
      unique: true,
    },

    // Regular full courses assigned to the teacher
    assignedCourses: [
      {
        courseId: { type: mongoose.Schema.Types.ObjectId, ref: "Course" },
      },
    ],

    // Demo courses assigned to the teacher (e.g., "Demo Guitar")
    assignedDemoCourses: [
      {
        demoCourseId: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "DemoCourse",
        },
      },
    ],
  },
  { timestamps: true }
);

module.exports = mongoose.model("TeacherDashboard", TeacherDashboardSchema);
