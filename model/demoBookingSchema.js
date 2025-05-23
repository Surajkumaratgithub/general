import mongoose from "mongoose";
import"./userModel.js";
const demoBookingSchema = new mongoose.Schema({
  studentId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  courseId: { type: mongoose.Schema.Types.ObjectId, ref: "DemoCourse", required: true },
  teacherId: { type: mongoose.Schema.Types.ObjectId, ref: "Teacher", required: true },
  date: { type: Date, required: true },
  slot: {
    startTime: {
          type: Date, required: true
    },
    endTime: {
          type: Date, required: true
    }

  },
  status: { type: String, enum: ["booked", "cancelled", "attended"], default: "booked" }
}, { timestamps: true });
 const DemoBooking = mongoose.model("DemoBooking",demoBookingSchema)
export default DemoBooking