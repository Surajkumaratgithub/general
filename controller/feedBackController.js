import Feedback from "../model/feedBackModel.js";

// Create Feedback
export const createFeedback = async (req, res) => {
  try {
    const { demoClassId, userId, rating, comment } = req.body;

    const feedback = new Feedback({
      demoClassId,
      userId,
      rating,
      comment,
    });

    await feedback.save();
    res.status(201).json({ message: "Feedback submitted", feedback });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
};

// Get Feedback by Demo Class
export const getFeedbackForDemo = async (req, res) => {
  try {
    const feedbacks = await Feedback.find({ demoClassId: req.params.demoClassId }).populate("userId");
    res.status(200).json(feedbacks);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};
