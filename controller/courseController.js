import Course from "../model/courses/courseModel.js";
import Session from "../model/courses/Session.js";
import Class from "../model/courses/Class.js";
import Teacher from "../model/teacherModel.js";
import uploadImageToCloudinary from "../utils/uploadImageToCloudinary.js";
import mongoose from "mongoose";
const cloudinaryFolder = "course_thumbnails";
import User from '../model/userModel.js'; 

// Create Course
export const createCourse = async (req, res) => {
  try {
    const {
      courseName,
      details,
      duration,
      mode,
      price,
      // assignedTeachers,
      batch,
      studentRange,
      status,
    } = req.body;

    // console.log(req.body);
    // Give the Url of the thubnail
    let thumbnailUrl = details?.thumbnail || null;

    if (thumbnailUrl) {
      // thumbnail size is under the 15MB limit
      const base64Size = Buffer.from(
        thumbnailUrl.split(",")[1],
        "base64"
      ).length;
      const maxSizeInBytes = 15 * 1024 * 1024;

      if (base64Size > maxSizeInBytes) {
        return res
          .status(400)
          .json({ error: "Thumbnail image exceeds 15 MB size limit" });
      }

      thumbnailUrl = await uploadImageToCloudinary(
        details.thumbnail,
        cloudinaryFolder
      );
    }

    // Convert single assignedTeacher string into ObjectId
    // const assignedTeacherId = new mongoose.Types.ObjectId(assignedTeacher);

    const course = new Course({
      courseName,
      details: {
        ...details,
        thumbnail: thumbnailUrl,
      },
      duration,
      mode,
      price,
      // assignedTeacher: assignedTeachers,
      batch,
      studentRange,
      status,
    });

    console.log(course);
    course.save();

    res.status(201).json({
      message: "Course successfully created!",
      course,
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
};

// // API route to fetch courses based on status
export const getAllCourses = async (req, res) => {
  const { status } = req.query;

  // If no status is provided, default to "All"
  const filter = status && status !== "All" ? { status } : {};
  console.log("filter course is:",filter);

  try {
    // Fetch courses based on the filter
    const courses = await Course.find(filter).populate({
      path: "assignedTeacher",
      populate: {
        path: "user",
      },
    });

    // Send the response with the courses
    res.status(200).json({ count: courses.length, courses });
  } catch (err) {
    // Handle any errors
    console.error(err);
    res.status(500).json({ message: "Error fetching courses" });
  }
};

// Get course by ID
export const getCourseById = async (req, res) => {
  try {
    const { courseId } = req.params;
    // Validate MongoDB ObjectId
    if (!mongoose.Types.ObjectId.isValid(courseId)) {
      return res.status(400).json({ error: "Invalid course ID format." });
    }

    const course = await Course.findById(courseId).populate({
      path: "assignedTeacher",
      select: "user",
      populate: {
        path: "user",
        select: "name", // only select name from user
      },
    });

    if (!course) return res.status(404).json({ error: "Course not found" });
    res.status(200).json(course);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// This is workfull for the toggle or one button to public
export const changeCourseStatus = async (req, res) => {
  try {
    const { courseId } = req.params;
    // Validate MongoDB ObjectId
    if (!mongoose.Types.ObjectId.isValid(courseId)) {
      return res.status(400).json({ error: "Invalid course ID format." });
    }

    const { status } = req.body;

    // Check if status is provided
    if (!status) {
      return res.status(400).json({ message: "Status is required" });
    }

    // Check if the provided status is valid
    const validStatuses = ["public", "draft"];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        message:
          "Invalid status value. Allowed values are: 'drafts', 'public'.",
      });
    }

    const course = await Course.findById(courseId);
    if (!course) {
      return res.status(404).json({ error: "Course not found." });
    }

    if (course.status === status) {
      return res
        .status(400)
        .json({ error: `Course is already in '${status}' status.` });
    }

    // Update the course status
    course.status = status;
    await course.save();

    // Return success response with updated course
    res.status(200).json({
      message: `Course status updated to '${status}' successfully.`,
      course,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// // Update course
// export const updateCourse = async (req, res) => {
//   try {
//     const { courseId } = req.params;
//     // Validate MongoDB ObjectId
//     if (!mongoose.Types.ObjectId.isValid(courseId)) {
//       return res.status(400).json({ error: "Invalid course ID format." });
//     }

//     const {
//       courseName,
//       details,
//       duration,
//       mode,
//       price,
//       assignedTeacher,
//       batch,
//       studentRange,
//       status,
//     } = req.body;

//     console.log(req.body);

//     console.log("hello");
//     console.log(assignedTeacher);
//     // Validation: required fields
//     if (!courseName || !duration || !mode || !price) {
//       return res.status(400).json({ message: "Missing required fields" });
//     }

//     if (duration.unit && !["month", "year"].includes(duration.unit)) {
//       return res.status(400).json({ message: "Invalid duration unit" });
//     }

//     if (mode && !["online", "offline"].includes(mode)) {
//       return res.status(400).json({ message: "Invalid course mode" });
//     }

//     // Check if course exists
//     const existingCourse = await Course.findById(courseId);
//     if (!existingCourse) {
//       return res.status(404).json({ error: "Course not found." });
//     }

//     // Convert single assignedTeacher string into ObjectId
//     // const assignedTeacherId = new mongoose.Types.ObjectId(assignedTeacher);

//     const teacherData = await Teacher.findById(assignedTeacher);
//     console.log(teacherData);

//     let updatedDetails = details;

//     console.log(updatedDetails);
//     // Handle thumbnail upload if provided
//     if (details?.thumbnail) {
//       const thumbnailUrl = await uploadImageToCloudinary(
//         details.thumbnail,
//         cloudinaryFolder
//       );
//       updatedDetails = {
//         ...details,
//         thumbnail: thumbnailUrl,
//       };
//     }

//     // Prepare update fields
//     const updatedFields = {
//       courseName,
//       details: updatedDetails,
//       duration,
//       mode,
//       price,
//       assignedTeacher,
//       batch,
//       studentRange,
//       status,
//     };

//     console.log(updatedFields);
//     const updatedCourse = await Course.findByIdAndUpdate(
//       courseId,
//       updatedFields,
//       {
//         new: true,
//         runValidators: true,
//       }
//     );
//     res
//       .status(200)
//       .json({ message: "Course updated successfully", course: updatedCourse });
//   } catch (error) {
//     res.status(400).json({ error: error.message });
//   }
// };


// Update course
export const updateCourse = async (req, res) => {
  try {
    const { courseId } = req.params;

    // Validate MongoDB ObjectId
    if (!mongoose.Types.ObjectId.isValid(courseId)) {
      return res.status(400).json({ error: "Invalid course ID format." });
    }

    const {
      courseName,
      details,
      duration,
      mode,
      price,
      assignedTeacher,
      batch,
      studentRange,
      status,
    } = req.body;

    // Check if course exists
    const existingCourse = await Course.findById(courseId);
    if (!existingCourse) {
      return res.status(404).json({ error: "Course not found." });
    }

    // Validate enums if provided
    if (duration?.unit && !["month", "year"].includes(duration.unit)) {
      return res.status(400).json({ message: "Invalid duration unit" });
    }

    if (mode && !["online", "offline"].includes(mode)) {
      return res.status(400).json({ message: "Invalid course mode" });
    }

    // Validate teacher if provided
    if (assignedTeacher) {
      const teacherData = await Teacher.findById(assignedTeacher);
      if (!teacherData) {
        return res.status(404).json({ error: "Assigned teacher not found." });
      }
    }

    let updatedDetails = details;

    // Handle thumbnail upload if provided
    if (details?.thumbnail) {
      const thumbnailUrl = await uploadImageToCloudinary(
        details.thumbnail,
        cloudinaryFolder
      );
      updatedDetails = {
        ...details,
        thumbnail: thumbnailUrl,
      };
    }

    // Build updated fields dynamically
    const updatedFields = {};
    if (courseName !== undefined) updatedFields.courseName = courseName;
    if (details !== undefined) updatedFields.details = updatedDetails;
    if (duration !== undefined) updatedFields.duration = duration;
    if (mode !== undefined) updatedFields.mode = mode;
    if (price !== undefined) updatedFields.price = price;
    if (assignedTeacher !== undefined) updatedFields.assignedTeacher = assignedTeacher;
    if (batch !== undefined) updatedFields.batch = batch;
    if (studentRange !== undefined) updatedFields.studentRange = studentRange;
    if (status !== undefined) updatedFields.status = status;

    // Perform update
    const updatedCourse = await Course.findByIdAndUpdate(courseId, updatedFields, {
      new: true,
      runValidators: true,
    });

    res.status(200).json({
      message: "Course updated successfully",
      course: updatedCourse,
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
};


// Delete course
export const deleteCourse = async (req, res) => {
  // try {
  //   const { courseId } = req.params;

  //   // Validate MongoDB ObjectId
  //   if (!mongoose.Types.ObjectId.isValid(courseId)) {
  //     return res.status(400).json({ error: "Invalid course ID format." });
  //   }

  //   // const course = await Course.findByIdAndDelete(courseId);

  //   const course = await Course.findById(courseId);
  //   if (!course) {
  //     return res.status(404).json({ error: "Course not found." });
  //   }
  //   await course.remove(); // Triggers session + class cascade delete


  //   if (!course) {
  //     return res.status(404).json({ error: "Course not found." });
  //   }

  //   res.status(200).json({ message: "Course deleted successfully." });
  // } catch (error) {
  //   res.status(500).json({ error: error.message });
  // }
  const { courseId } = req.params;
  try {
    const course = await Course.findById(courseId);
    if (!course) return res.status(404).json({ message: 'Course not found' });

    // Find all sessions under this course
    const sessions = await Session.find({ course: courseId });

    // For each session, trigger removal (which will auto-delete its classes)
    for (let session of sessions) {
      await Class.deleteMany({ session: session._id });
    }
    await Session.deleteMany({ course: courseId });
    

    // Delete the course itself
    await course.deleteOne();

    res.json({ message: 'Course, sessions, and all related classes deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

// Need to merge with the create course or update course
export const assignedTeachers = async (req, res) => {
  try {
    const { teacherId, courseId, startTime, endTime } = req.body;

    // Step 1: Fetch teacher
    const teacher = await Teacher.findById(teacherId).populate("courses");
    if (!teacher) return res.status(404).json({ message: "Teacher not found" });

    // Step 2: Check time conflict
    const toMinutes = (timeStr) => {
      const [hours, minutes] = timeStr.split(":").map(Number);
      return hours * 60 + minutes;
    };

    const newStart = toMinutes(startTime);
    const newEnd = toMinutes(endTime);

    const isConflict = teacher.courses.some((course) => {
      const courseTeacher = course.assignedTeacher.find(
        (id) => id.toString() === teacherId
      );
      if (!courseTeacher) return false;

      const existingStart = toMinutes(teacher.studySlot.startTime);
      const existingEnd = toMinutes(teacher.studySlot.endTime);

      return (
        (newStart >= existingStart && newStart < existingEnd) ||
        (newEnd > existingStart && newEnd <= existingEnd) ||
        (newStart <= existingStart && newEnd >= existingEnd)
      );
    });

    if (isConflict) {
      return res.status(400).json({
        message:
          "Time slot conflict! Teacher is already assigned during this slot.",
      });
    }

    // Step 3: Assign course
    const course = await Course.findById(courseId);
    if (!course) return res.status(404).json({ message: "Course not found" });

    if (!teacher.courses.includes(courseId)) {
      teacher.courses.push(courseId);
      await teacher.save();
    }

    if (!course.assignedTeacher.includes(teacherId)) {
      course.assignedTeacher.push(teacherId);
      await course.save();
    }

    res.status(200).json({ message: "Course assigned successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
};


   
// Sessions export const
export const createSession = async (req, res) => {

  // const { courseId } = req.params;
   // const course = await Course.findById(courseId);
  // if (!course) return res.status(404).json({ message: 'Course not found' });
   try {
    const {title, description, startDate, endDate } = req.body;
    const { courseId } = req.params;
  
      if (!mongoose.Types.ObjectId.isValid(courseId)) {
        return res.status(400).json({ error: "Invalid course ID." });
      }

      const session = new Session({
        course: courseId,
        title,
        description,
        startDate,
        endDate,
      });
  
      await session.save();
      res.status(201).json({ message: "Session created", session });
    }
     catch (error) {
      res.status(500).json({ error: error.message });
    }
  }


export const getSessionsByCourse = async (req, res) => {
   try {
    const { courseId } = req.params;
    const sessions = await Session.find({ course: courseId });
    res.status(200).json({ sessions });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

export const updateSession = async (req, res) => {
  try {
    const { sessionId } = req.params;
    const updates = req.body;
    const updatedSession = await Session.findByIdAndUpdate(sessionId, updates, {
      new: true,
      runValidators: true,
    });
    res.status(200).json({ message: "Session updated", updatedSession });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// export const deleteSession = async (req, res) => {
//   try {
//     const session = await Session.findById(req.params.sessionId);
//     if (!session) return res.status(404).json({ error: "Session not found" });
//     const sessions = await Session.find({ course: courseId });

//     // For each session, trigger removal (which will auto-delete its classes)
//     for (let session of sessions) {
//       await Class.deleteMany({ session: session._id });
//     }

//     await session.deleteOne(); // triggers cascade delete of classes
//     res.status(200).json({ message: "Session deleted" });
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// };

export const deleteSession = async (req, res) => {
  try {
    const { courseId, sessionId } = req.params;
    console.log(courseId,"hhhhh",sessionId);

    const session = await Session.findById(sessionId);
    if (!session) return res.status(404).json({ error: "Session not found" });

    // Delete classes under that session only
    await Class.deleteMany({ session: sessionId });

    await session.deleteOne(); // Delete the session
    res.status(200).json({ message: "Session deleted" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};




// ----------------- Class APIs -----------------

export const createClass = async (req, res) => {
  try {
    const { topic, scheduledDate, durationMinutes, resources } = req.body;
     const {sessionId} = req.params;
    
    //  console.log(req.params);
     
    if (!mongoose.Types.ObjectId.isValid(sessionId)) {
      return res.status(400).json({ error: "Invalid session ID" });
    }

    const newClass = new Class({
      session: sessionId,
      topic,
      // scheduledDate,
      durationMinutes,
      resources,
    });

    await newClass.save();
    res.status(201).json({ message: "Class created", newClass });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
}


// export const getClassesBySession = async (req, res) => {
//   const { courseId, sessionId } = req.params;
//   console.log(req.params);
  
//   const session = await Session.findOne({ _id: sessionId, courseId });
//   console.log(session);
  
//   if (!session) return res.status(404).json({ message: 'Session not found' });

//   const classes = await Class.find({ sessionId });
//   res.json(classes);
// };
export const getClassesBySession = async (req, res) => {
  const { courseId, sessionId } = req.params;
  // console.log("Params:", req.params);

  try {
    const session = await Session.findOne({
      _id: new mongoose.Types.ObjectId(sessionId),
      course: new mongoose.Types.ObjectId(courseId),
    });

    if (!session) {
      return res.status(404).json({ message: 'Session not found' });
    }

    const classes = await Class.find({ session: sessionId });
    return res.json(classes);
    

  } catch (error) {
    console.error("Error in getClassesBySession:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};


export const updateClass = async (req, res) => {
  try {
    const { courseId, sessionId, classId } = req.params;

    const trimmedCourseId = courseId.trim();
    const trimmedSessionId = sessionId.trim();
    const trimmedClassId = classId.trim();

    // Validate session exists under the given course
    const session = await Session.findOne({ _id: trimmedSessionId, course: trimmedCourseId });
    if (!session) return res.status(404).json({ message: 'Session not found' });

    // Use correct session field name from Class model
    const updatedClass = await Class.findOneAndUpdate(
      { _id: trimmedClassId, session: trimmedSessionId },
      req.body,
      { new: true }
    );

    if (!updatedClass) return res.status(404).json({ message: 'Class not found' });

    res.json(updatedClass);
  } catch (error) {
    console.error("Update Class Error:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
};



export const deleteClass = async (req, res) => {
  const { courseId, sessionId, classId } = req.params;

  try {
    const session = await Session.findOne({
      _id: new mongoose.Types.ObjectId(sessionId),
      course: new mongoose.Types.ObjectId(courseId),
    });

    if (!session) {
      return res.status(404).json({ message: 'Session not found' });
    }

    const deletedClass = await Class.findOneAndDelete({
      _id: new mongoose.Types.ObjectId(classId),
      session: sessionId,
    });

    if (!deletedClass) {
      return res.status(404).json({ message: 'Class not found' });
    }

    res.json({ message: 'Class deleted' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
};