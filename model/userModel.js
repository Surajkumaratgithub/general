import mongoose from "mongoose";
import bcrypt from "bcrypt";

const userSchema = new mongoose.Schema(
  {
    name: {
      firstName: { type: String, required: true, trim: true },
      lastName: { type: String, required: true, trim: true },
    },
    // age: { type: Number }, // Consider making this dynamic instead of storing it
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    mobileNumber: {
      type: String,
      unique: true,
    },
    branch: {
      type: mongoose.Types.ObjectId,
      ref: "Branch",
    },
    password: { type: String },
    mode: {
      type: String,
      enum: ["online", "offline"]
    },
    role: {
      type: String,
      enum: ["user", "teacher", "admin", "superadmin",'student','demostudent'],
      default: "user",
    },
  },
  { timestamps: true }
);

// Hash password before saving
userSchema.pre("save", async function (next) {
  if (this.isModified("password")) {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
  }
  next();
});

// Optional: Add method to compare password (for login)
userSchema.methods.comparePassword = async function (plainPassword) {
  return await bcrypt.compare(plainPassword, this.password);
};

const User = mongoose.model("User", userSchema);
export default User;
