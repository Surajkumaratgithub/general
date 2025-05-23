import mongoose from "mongoose";
import bcrypt from "bcrypt";

const studentSchema = new mongoose.Schema(
  {
    studentId: { type: String, unique: true },
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: [true, "User reference is required."],
      unique: true,
      
    },
    dob: { type: Date },
    notifications: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Notification",
      },
    ],
    bookedSets: {
      demoCourses: [
        {
          type: mongoose.Schema.Types.ObjectId,
          ref: "DemoCourse",
        },
      ],
      courses: [
        {
          type: mongoose.Schema.Types.ObjectId,
          ref: "Course",
        },
      ],
    },
    password: { type: String, required: true },
  },
  { timestamps: true }
);

// convert password hashing and student ID generation
studentSchema.pre("save", async function (next) {
  try {
    if (this.isModified("password")) {
      const salt = await bcrypt.genSalt(10);
      this.password = await bcrypt.hash(this.password, salt);
    }

    if (this.isNew && !this.studentId) {
      let isUnique = false;
      let generatedId = "";
      let length = 4;

      while (!isUnique) {
        const randomSuffix = Math.floor(Math.random() * Math.pow(15, length)); // Random part with `length` digits
        generatedId = `S${randomSuffix.toString().padStart(length, "0")}`;

        isUnique = await isUniqueStudentId(generatedId);

        if (!isUnique) {
          length++;
        }
      }

      this.studentId = generatedId;
    }

    next();
  } catch (error) {
    next(error);
  }
});

const isUniqueStudentId = async (studentId) => {
  const existingStudent = await mongoose
    .model("Student")
    .findOne({ studentId });
  return !existingStudent;
};

const Student = mongoose.model("Student", studentSchema);
export default Student;
