import mongoose from "mongoose";

const AttendanceSchema = new mongoose.Schema({
  course: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Course",
    required: true,
  },
  meetingId: {
    type: String,
  },
  teacher: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Teacher",
    required: true,
  },
  joinTime: {
    type: Date,
    required: true,
  },
  leaveTime:{   type: Date,
    required: true
  },
    userType:  {
    type: String,
  },
  status: {
    type: String,
    enum: ["Present", "Absent"],
    default: "Present",
  },
});
const Attendance = mongoose.model("Attendance", AttendanceSchema);
export default Attendance;
