import mongoose from "mongoose"

const meetingSchema = new mongoose.Schema({
  user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: [true, "User reference is required."],
      unique: true,
    },
  subject: String,
  startDateTime: Date,
  endDateTime: Date,
  joinUrl: String,
  meetingId: String,
});
const Meeting = mongoose.model("Meeting", meetingSchema);
export default Meeting;
