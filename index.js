import express from "express";
// import userRouter from "./routes/userRoutes.js";
import database from "./config/database.js";
import cookieParser from "cookie-parser";
import cors from "cors";
import dotenv from "dotenv";
import "./model/userModel.js"; 
// import studentRoutes from "./routes/studentRoutes.js";
// import courseRoutes from "./routes/courseRoutes.js";
// import teacherRoutes from "./routes/teacherRoutes.js";
// import teachersApplicationRoutes from "./routes/teachersApplicationRoutes.js";
// import demoCoursesRoutes from "./routes/demoCoursesRoutes.js";
// import feedbackRoutes from "./routes/feedBackRoutes.js";
// import queryRoutes from "./routes/queryRoutes.js";
// import notificationRoutes from "./routes/notificationRoutes.js";
// import contactUsRoutes from "./routes/contactUsRoutes.js";
// import branchRoute from "./routes/branchRoute.js";
// import adminRoute from "./routes/adminRoutes.js";
// import teacherRatingRoutes from "./routes/teacherRatingRoutes.js";
// import loginRoutes from "./routes/loginRoutes.js";
// import assignmentSubmissionRoutes from "./routes/assignmentSubmissionRoutes.js";
import "./cron/updateAssignmentType.js";
import lazyLoadRoute from "./utils/lazyLoadRoute.js";

const app = express();

const PORT = process.env.PORT || 5000;
dotenv.config();

app.use(express.json({ limit: "200mb" }));
app.use(express.urlencoded({ limit: "200mb", extended: true }));
app.use(cookieParser());
// app.use(cors({ origin: "*", credentials: true }));
app.use(cors({
    origin: ['http://localhost:3000', 'http://localhost:5173'],  // ✅ Must match your frontend origin
    credentials: true                 // ✅ Allow credential(cookies, auth headers)
}));

//hello world

// // app.use("/api/auth/user", userRouter);
// app.use("/api/auth", loginRoutes);

// // Routes
// app.use("/api/v1/teacher", teacherRoutes);

// app.use("/api/v1/teacher-applications", teachersApplicationRoutes);

// app.use("/api/v1/student", studentRoutes);
// app.use("/api/v1/course", courseRoutes);
// app.use("/api/v1/demos", demoCoursesRoutes);
// app.use("/api/v1/feedback", feedbackRoutes);
// app.use("/api/v1/query", queryRoutes);
// app.use("/api/v1/notifications", notificationRoutes);
// app.use("/api/v1/contactUs", contactUsRoutes);
// app.use("/api/v1/branch", branchRoute);
// app.use("/api/v1/admin", adminRoute);
// app.use("/api/v1/teacherRating", teacherRatingRoutes);
// app.use("/api/v1/assignment", assignmentSubmissionRoutes);
app.use('/api/v1/time-slots',lazyLoadRoute('./routes/timeSlotRoutes.js'))
app.use("/api/v1/demo-bookings",lazyLoadRoute('./routes/demoBookingRoutes.js') );
app.use("/api/v1/demo-students",lazyLoadRoute("./routes/demoStudentRoutes.js"));
app.use("/api/v1/auth", lazyLoadRoute("./routes/loginRoutes.js"));
app.use("/api/v1/student", lazyLoadRoute("./routes/studentRoutes.js"));
app.use("/api/v1/teacher", lazyLoadRoute("./routes/teacherRoutes.js"));
app.use("/api/v1/course", lazyLoadRoute("./routes/courseRoutes.js"));
app.use("/api/v1/demos", lazyLoadRoute("./routes/demoCoursesRoutes.js"));
app.use("/api/v1/feedback", lazyLoadRoute("./routes/feedBackRoutes.js"));
app.use("/api/v1/query", lazyLoadRoute("./routes/queryRoutes.js"));
app.use("/api/v1/notifications", lazyLoadRoute("./routes/notificationRoutes.js"));
app.use("/api/v1/contactUs", lazyLoadRoute("./routes/contactUsRoutes.js"));
app.use("/api/v1/branch", lazyLoadRoute("./routes/branchRoutes.js"));
app.use("/api/v1/admin", lazyLoadRoute("./routes/adminRoutes.js"));
app.use("/api/v1/teacherRating", lazyLoadRoute("./routes/teacherRatingRoutes.js"));
app.use("/api/v1/assignment", lazyLoadRoute("./routes/assignmentSubmissionRoutes.js"));
app.use("/api/v1/admission", lazyLoadRoute("./routes/admissionRoutes.js"));
app.use("/api/v1/teacher-applications", lazyLoadRoute("./routes/teachersApplicationRoutes.js"));


app.get("/", (req, res) => {
  return res.json({
    success: true,
    message: "Your server is up and running...",
  });
});

//checking git new branch


app.use((error, req, res, next) => {
  console.error("Error:", error);
  console.log(error.statusCode);
  res.status(error.statusCode || 500).json({ message: error._message });
});
database().then(() => {
  app.listen(PORT, () => {
  console.log(`App is listening at ${PORT}`);
});
});


export default app;
