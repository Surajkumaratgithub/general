import mongoose from "mongoose";

const demoCoursesSchema = new mongoose.Schema(
  {
    subject: { type: String, required: true, trim: true },
    description: { type: String, trim: true },
    teachers:[{
      type: mongoose.Schema.Types.ObjectId,
      ref: "Teacher",
    }], 
    // This is for the vocal , dance , singing
    category: { type: String, required: true, trim: true },
    scheduleAt: { type: Date },
    duration: { type: String },

    requirements: [{ type: String }],
    syllabus: [{ type: String }],

    courseThumbnail: {
      type: String,
      required: true,
    },
    reviews: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Review",
      },
    ],

    availableSeats: { type: Number, required: true, min: 1 },
    bookedSeats: { type: Number, default: 0, min: 0 },

    // this is for the public and drafts
    isActive: { type: Boolean, default: true },

    mode: { type: String, enum: ["online", "offline"], required: true },
  },
  { timestamps: true }
);

const DemoCourse = mongoose.model("DemoCourse", demoCoursesSchema);
export default DemoCourse;
