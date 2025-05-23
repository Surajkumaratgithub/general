import mongoose from "mongoose";

const NotificationSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: true,
      trim: true,
    },
    description: {
      type: String,
      required: true,
      trim: true,
    },
    sentAt: {
      type: Date,
      default: Date.now,
    },
    targetType: {
      type: String,
      enum: ["all", "students", "teachers", "student", "teacher"],
      required: true,
    },
    user: {
      type: mongoose.Schema.Types.ObjectId,
      refPath: "userModel",
      default: null,
    },
    userModel: {
      type: String,
      enum: ["Student", "Teacher", null],
      default: null,
    },
    // isRead: {
    //   type: Boolean,
    //   default: false,
    // },
  },
  { timestamps: true }
);

NotificationSchema.index({ user: 1, sentAt: -1 });

export default mongoose.model("Notification", NotificationSchema);
