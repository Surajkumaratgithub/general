import axios from "axios"
import Attendance from "../models/Attendance"
import Meeting from "../models/Meeting";

export const fetchAndSaveAttendance = async (req, res) => {
  const { meetingId } = req.params;
  const accessToken = req.cookies.msToken

  try {
    // const reports = await axios.get(
    //   `https://graph.microsoft.com/v1.0/me/onlineMeetings/${meetingId}/attendanceReports`,
    //   { headers: { Authorization: `Bearer ${accessToken}` } }
    // );

    // const reportId = reports.data.value[0].id;

    // const records = await axios.get(
    //   `https://graph.microsoft.com/v1.0/me/onlineMeetings/${meetingId}/attendanceReports/${reportId}/attendanceRecords`,
    //   { headers: { Authorization: `Bearer ${accessToken}` } }
    // );

    const saved = await Promise.all(records.data.value.map(record => {
      return Attendance.create({
        meetingId,
        userId: record.identity.user.id || null,
        userType: record.role.toLowerCase(),
        joinTime: record.joinDateTime,
        leaveTime: record.leaveDateTime,
        durationMinutes: Math.floor(
          (new Date(record.leaveDateTime) - new Date(record.joinDateTime)) / 60000
        ),
      });
    }));

    res.json({ message: "Attendance saved", saved });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch/save attendance", details: err.message });
  }
};

export const getAttendanceByMeeting = async (req, res) => {
  try {
    const records = await Attendance.find({ meetingId: req.params.meetingId });
    res.json(records);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch attendance" });
  }
};
