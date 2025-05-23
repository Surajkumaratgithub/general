// models/Session.js
import mongoose from "mongoose";
import Class from "./Class.js";

const sessionSchema = new mongoose.Schema(
  {
    course: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Course",
      required: true,
    },
    title: { type: String, required: true },
    description:{type: String},
  },

  { timestamps: true }
);

sessionSchema.pre("deleteOne", async function (next) {
  try {
    await Class.deleteMany({ session: this._id });
    next();
  } catch (err) {
    next(err);
  }
});


const Session = mongoose.model("Session", sessionSchema);
export default Session;
