import Notification from "../model/notificationModel.js";
import Student from "../model/studentModel.js";
import Teacher from "../model/teacherModel.js";

export const createNotification = async (req, res) => {
  try {
    const { title, description, targetType } = req.body;

    if (!title || !description || !targetType) {
      return res.status(400).json({
        success: false,
        message: "Title, description, and targetType are required.",
      });
    }

    if (!["students", "teachers", "all"].includes(targetType)) {
      return res.status(400).json({
        success: false,
        message: 'targetType must be "students", "teachers", or "all".',
      });
    }

    // Create one notification document
    const notification = await Notification.create({
      title,
      description,
      targetType,
    });

    // Push to all students, teachers, or both
    if (targetType === "students" || targetType === "all") {
      const studentCount = await Student.countDocuments();
      if (studentCount > 0) {
        await Student.updateMany(
          {},
          { $push: { notifications: notification._id } }
        );
      }
    }

    if (targetType === "teachers" || targetType === "all") {
      const teacherCount = await Teacher.countDocuments();
      if (teacherCount > 0) {
        await Teacher.updateMany(
          {},
          { $push: { notifications: notification._id } }
        );
      }
    }

    return res.status(201).json({
      success: true,
      message: "Notification sent successfully",
      notification,
    });
  } catch (error) {
    console.error("Error sending notification:", error);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

// Get all notifications
export const getAllNotifications = async (req, res) => {
  try {
    const notifications = await Notification.find()
      // .populate("user", "name email")
      .select("title description sentAt targetType")
      .sort({ sentAt: -1 });

    if (notifications.length === 0) {
      return res.status(404).json({
        success: false,
        message: "No notifications found",
      });
    }

    res.status(200).json({
      success: true,
      data: notifications,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

// Get a single notification by ID
// export const getNotificationById = async (req, res) => {
//   try {
//     const notification = await Notification.findById(req.params.id)
//       .populate("student", "name email")
//       .populate("teacher", "name email");

//     if (!notification) {
//       return res
//         .status(404)
//         .json({ success: false, message: "Notification not found" });
//     }

//     res.json({ success: true, data: notification });
//   } catch (error) {
//     res.status(500).json({ success: false, message: error.message });
//   }
// };

// Delete the Notifcation
export const deleteNotification = async (req, res) => {
  try {
    const { id } = req.params;

    const notification = await Notification.findById(id);
    if (!notification) {
      return res.status(404).json({
        success: false,
        message: "Notification not found",
      });
    }

    const { targetType, user, userModel } = notification;

    // Remove notification reference based on its target
    if (["student", "teacher"].includes(targetType) && user && userModel) {
      const Model = userModel === "Student" ? Student : Teacher;
      await Model.findByIdAndUpdate(user, {
        $pull: { notifications: id },
      });
    } else if (targetType === "students") {
      await Student.updateMany({}, { $pull: { notifications: id } });
    } else if (targetType === "teachers") {
      await Teacher.updateMany({}, { $pull: { notifications: id } });
    } else if (targetType === "all") {
      await Promise.all([
        Student.updateMany({}, { $pull: { notifications: id } }),
        Teacher.updateMany({}, { $pull: { notifications: id } }),
      ]);
    }

    // Now delete the notification itself
    await Notification.findByIdAndDelete(id);

    return res.status(200).json({
      success: true,
      message: "Notification deleted successfully",
    });
  } catch (error) {
    console.error("Error deleting notification:", error);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};
