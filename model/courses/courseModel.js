import mongoose from "mongoose";
import Session from "./Session.js";

const courseSchema = new mongoose.Schema(
  {
    courseName: { type: String, required: true },
    details: {
      modules: [{ type: String }],
      description: { type: String },
      thumbnail: { type: String },
    },
    duration: {
      value: { type: Number, required: true },
      unit: { type: String, enum: ["month", "year"], required: true },
    },
    mode: { type: String, enum: ["online", "offline"], required: true },
    price: { type: Number, required: true },
    assignedTeacher: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Teacher",
    },
    batch: { type: String }, // e.g., "Batch A", "2025", etc.
    totalEnrollment: { type: Number, default: 0 },
    studentRange: {
      min: { type: Number, default: 1 },
      max: { type: Number },
    },
    status: {
      type: String,
      enum: ["All", "public", "draft"],
      default: "draft", // start as draft by default
    },
  },
  { timestamps: true }
);

// Cascade delete sessions when course is removed
// courseSchema.pre("remove", async function (next) {
//   try {
//     await Session.deleteMany({ course: this._id });
//     next();
//   } catch (err) {
//     next(err);
//   }
// });
courseSchema.pre(
  "deleteOne",
  { document: true, query: false },
  async function (next) {
    const courseId = this._id;
    const sessions = await Session.find({ course: courseId });

    for (let session of sessions) {
      await Class.deleteMany({ session: session._id });
    }

    await Session.deleteMany({ course: courseId });

    next();
  }
);

const Course = mongoose.model("Course", courseSchema);
export default Course;

// const courseSchema =
