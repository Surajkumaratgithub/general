import mongoose from "mongoose";

const otpSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
  },
  otp: {
    type: String,
    required: true,
  },
  verified: {
    type: Boolean,
    default: false, // starts as false, becomes true after successful verification
  },
  createdAt: {
    type: Date,
    default: Date.now,
    expires: 600, // Document expires after 10 mins
  },
});

const Otp = mongoose.model("Otp", otpSchema);
export default Otp;
