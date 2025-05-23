import mongoose from "mongoose";

const assignmentSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: true,
    },
    description: {
      type: String,
      default: "",
    },
    // dueDate is null when assigment is in the draft
    dueDate: {
      // Due Date is only set when the status is public or the dueData is in future
      type: Date,
      required: function () {
        return this.status === "public";
      },
      validate: {
        validator: function (value) {
          return this.status !== "public" || value >= new Date();
        },
        message: "Due date cannot be in the past for public assignments",
      },
    },
    course: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Course",
      required: true,
    },
    status: {
      type: String,
      enum: ["draft", "public"],
      default: "draft",
      required: true,
    },
    // This will automatic update in 12'o clock to make it expired
    deadlineStatus: {
      type: String,
      enum: ["active", "expired", "draft"], // draft mean no deadline
      default: "draft",
    },
    // This come by JWT
    teacher: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Teacher",
      required: true,
    },
    // for url it's depend on how the teacher provide the assignment
    // resources: {
    //   type: [String],
    //   default: [],
    // },
  },
  { timestamps: true }
);

const Assignment = mongoose.model("Assignment", assignmentSchema);
export default Assignment;
