import axios from "axios";
import Meeting from "../model/courses/MeetingModel.js";
import generateMSGraphApiToken from "../utils/generateMSGraphApiToken.js";

export const scheduleMeeting = async (req, res) => {
  const { subject,email } = req.body;
  const accessToken = await generateMSGraphApiToken();

  const startDateTime = new Date().toISOString();
  const endDateTime = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 hour later

  try {
//     const userInfo = await axios.get(`https://graph.microsoft.com/v1.0/users/${email}`, {
//   headers: {
//     Authorization: `Bearer ${accessToken}`
//   }
// });
//     const userId = userInfo.data.id;
//     console.log(userId)

const response = await axios.post(
  `https://graph.microsoft.com/v1.0/users/34ea6950-1aba-4fac-aea7-375df21ddf58/onlineMeetings`,
  {
    subject,
    startDateTime,
    endDateTime
  },
  {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json"
    }
  }
);
    
// console.log(response)

    const meeting = await Meeting.create({
      teacherId: req.user._id,
      subject,
      startDateTime,
      endDateTime,
      joinUrl: response.data.joinWebUrl,
      meetingId: response.data.id,
    });

    res.status(201).json({ message: "Meeting scheduled", meeting });
  } catch (error) {
    console.log(error.response?.data || error);
    res.status(500).json({
      error: "Failed to schedule meeting",
      message: error.message,
      details: error.response?.data || null
    });
  }
};

export const getAllMeetingsForUser = async (req, res) => {
  try {
    const meetings = await Meeting.find();
    res.json(meetings);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch meetings" });
  }
};

export const getMeetingDetails = async (req, res) => {
  try {
    const meeting = await Meeting.findById(req.params.id);
    res.json(meeting);
  } catch (error) {
    res.status(404).json({ error: "Meeting not found" });
  }
};
