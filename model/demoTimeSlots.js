import mongoose from "mongoose";

const slotSchema = new mongoose.Schema({
  start: { type: Date, required: true },
  end: { type: Date, required: true },
}, { _id: false });

const demoTimeSlotSchema = new mongoose.Schema({
  courseId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "DemoCourse",
    required: true,
  },
  teacherId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Teacher",
    required: true,
  },
  date: { type: Date, required: true }, // The specific day
  slots: [slotSchema], // Time slots within that day
}, { timestamps: true });

const DemoTimeSlot = mongoose.model("DemoTimeSlot", demoTimeSlotSchema);
export default DemoTimeSlot;
