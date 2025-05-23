import mongoose from "mongoose";

const feedbackSchema = new mongoose.Schema({
  demoClassId: { type: mongoose.Schema.Types.ObjectId, ref: "DemoClass", required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "Student", required: true },
  rating: { type: Number, min: 1, max: 5 },
  comment: { type: String },
  submittedAt: { type: Date, default: Date.now },
});

const Feedback = mongoose.model("Feedback", feedbackSchema);
export default Feedback;
