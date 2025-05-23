import mongoose from "mongoose";
import User from "./userModel.js";

const teacherSchema = new mongoose.Schema(
  {
    teacherId: {
      type: String,
      unique: true,
    },
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: [true, "User reference is required."],
      unique: true,
    },
    alternativeNumber: {
      type: String,
      trim: true,
    },
    address: {
      // addressLine: { type: String, trim: true },
      city: { type: String, trim: true },
      country: { type: String, trim: true },
      zipCode: {
        type: String,
        trim: true,
      },
    },
    // Biographical Info
    dob: {
      type: Date,
      // required: [true, "Date of birth is required."],
      validate: {
        validator: (v) => v < new Date(),
        message: "Date of birth must be in the past.",
      },
    },
    maritalStatus: {
      type: String,
      enum: ["Single", "Married", "Divorced"],
      required: [true, "Marital status is required."],
    },
    religion: {
      type: String,
      enum: ["Hindu", "Muslim", "Christian", "Sikh", "Other"],
    },
    citizenship: { type: String },
    gender: {
      type: String,
      enum: ["Male", "Female", "Other"],
    },
    photo: { type: String, trim: true },
    resume: { type: String, trim: true },
    
    // // Positional Info
    // department: {
    //   type: String,
    //   required: [true, "Department is required."],
    // },

    dutyType: {
      type: String,
      enum: ["Full Time", "Part Time"],
    },
    joiningDate: {
      type: Date,
      default: Date.now,
    },
    payFrequency: {
      type: String,
      enum: ["Weekly", "Biweekly", "Monthly", "Annual"],
      required: [true, "Pay frequency is required."],
    },
    payFrequencyText: {
      type: String,
      // required: true,
    },
    salary: {
      type: Number,
      required: [true, "Salary is required."],
      min: [0, "Salary cannot be negative."],
    },
    hourlyRate: {
      type: Number,
      min: [0, "Hourly rate cannot be negative."],
    },

    // Reference to Bank Details
    bankDetails: {
      bankName: { type: String, required: true },
      branchName: { type: String, required: true },
      accountNumber: { type: String, required: true },
      accountHolderName: { type: String, required: true },
      accountHolderType: {
        type: String,
        enum: ["Saving", "Salary", "Current"],
      },
      ifscCode: { type: String, required: true },
    },
    assignedDemoCourses:[{ type: mongoose.Schema.Types.ObjectId,ref:'DemoCourse'}],
    status: {
      type: String,
      enum: ["Active", "Resigned", "Terminated"],
      default: "Active",
    },

    notifications: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Notification",
      },
    ],

    // // this is not in the form
    // education: {
    //   degree: { type: String, trim: true },
    //   branch: { type: String, trim: true },
    // },
    // experience: { type: Number, min: 0 },

    // studySlot: {
    //   startTime: { type: String, trim: true },
    //   endTime: { type: String, trim: true },
    // },

    teachingMode: {
      type: String,
      enum: ["online", "offline"],
      default: "online",
    }, 
    // languages: {
    //   type: [String],
    //   default: ["English"],
    // },
  },
  { timestamps: true }
);

// Check user role = "teacher"
teacherSchema.pre("save", async function (next) {
  const user = await User.findById(this.user);
  if (!user || user.role !== "teacher") {
    return next(new Error("Linked user must have role 'teacher'."));
  }
  next();
});

teacherSchema.pre("save", async function (next) {
  if (this.isNew && !this.teacherId) {
    let isUnique = false;
    let generatedId = "";
    let length = 4; // Start with 4 digits

    while (!isUnique) {
      // Generate teacher ID
      const randomSuffix = Math.floor(Math.random() * Math.pow(15, length)); // Random part with `length` digits
      generatedId = `E${randomSuffix.toString().padStart(length, "0")}`;

      // Check if the generated ID is unique
      isUnique = await isUniqueTeacherId(generatedId);

      if (!isUnique) {
        // If duplicate, increase length by 1 digit
        length++;
      }
    }
    this.teacherId = generatedId;
  }
  next();
});

const isUniqueTeacherId = async (teacherId) => {
  const existingTeacher = await mongoose
    .model("Teacher")
    .findOne({ teacherId });
  return !existingTeacher; // Returns true if the ID is unique, false if duplicate
};

const Teacher = mongoose.model("Teacher", teacherSchema);
export default Teacher; 
