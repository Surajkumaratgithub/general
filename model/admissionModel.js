import mongoose from "mongoose";

const admissionSchema = new mongoose.Schema({
  studentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Student", // assuming your student
    required: true,
  },
  courseId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Course", // assuming you have a Course model
    required: true,
  },
  mode: {
    type: String,
    enum: ["Online", "Offline"],
    required: true,
  },
  branch: {
    type: String,
    required: true,
  },
  admissionDate: {
    type: Date,
    default: Date.now,
  },
  paymentStatus: {
    type: String,
    enum: ["Pending", "Paid", "Failed"],
    default: "Pending",
  },
});

const Admission = mongoose.model('Admission', admissionSchema);

export default Admission;
