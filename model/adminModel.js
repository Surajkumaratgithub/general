import mongoose from "mongoose";

const adminSchema = new mongoose.Schema({
  user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: [true, "User reference is required."],
      unique: true,
  },
    // accessControlls:[{}]
})

const admin = mongoose.model("admin", adminSchema);

export default admin;
