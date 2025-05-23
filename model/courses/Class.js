// models/Class.js
import mongoose from "mongoose";
import Session from "./Session.js";

const classSchema = new mongoose.Schema(
  {
    session: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Session",
      required: true,
    },
    topic: { type: String, required: true },
    scheduledDate: { type: Date },
    durationMinutes: { type: Number },
    resources: { type: String }, // optional link or file URL
  },
  { timestamps: true }
);

const Class = mongoose.model("Class", classSchema);
export default Class;
