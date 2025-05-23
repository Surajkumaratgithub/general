import mongoose from "mongoose";

const teacherApplicationSchema = new mongoose.Schema(
  {
    // Personal Details
    name: {
      firstName: { type: String, required: true, trim: true },
      lastName: { type: String, required: true, trim: true },
    },
    mobileNumber: { type: Number, required: true, trim: true },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    address: {
      addressLine: { type: String, required: true, trim: true },
      city: { type: String, required: true, trim: true },
      state: { type: String, required: true, trim: true },
      country: { type: String, required: true, trim: true },
    },
    description: { type: String, required: true, trim: true },
    experience: { type: Number, required: true, min: 0 },
    photo: { type: String, trim: true }, // URL to teacher's photo
    resume: { type: String, required: true }, // Resume store in cloudiary
    videoConsent: { type: String, trim: true, required: true }, // Microsoft Teams storage URL
    teachingMode: {
      type: String,
      enum: ["online", "offline"],
      default: "online",
    },
    // designation: {
    //   type: String,
    // },
    skill: {
      type: String,
      required: true,
    },
    languages: {
      type: [String],
      default: ["English"],
    },
    status: {
      type: [String],
      enum: ["pending", "accept", "reject", "interview"],
      default: "pending",
    },
  },
  { timestamps: true }
);

// Export the model
export default mongoose.model("TeacherApplication", teacherApplicationSchema);
