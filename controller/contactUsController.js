import ContactUs from "../model/contactUsModel.js";
import validator from "validator";
import formatUserData from "../utils/formatInput.js";

import mongoose from "mongoose";

// Submit Contact Us Form
export const submitContactUsForm = async (req, res) => {
  try {
    const formatData = formatUserData(req.body);
    const { name, email, phone, message } = formatData;

    // Validate if all fields are provided
    if (!name || !email || !phone || !message) {
      return res.status(400).json({ error: "All fields are required" });
    }

    // Validate name
    if (typeof name !== "string" || name.trim().length < 2) {
      return res
        .status(400)
        .json({ error: "Name must be at least 2 characters" });
    }

    // Validate email
    if (!validator.isEmail(email)) {
      return res.status(400).json({ error: "Invalid email address" });
    }

    // Validate phone number (basic: must be numeric and 8 to 15 digits)
    if (!validator.isMobilePhone(phone, "any", { strictMode: false })) {
      return res.status(400).json({ error: "Invalid phone number" });
    }

    // Validate message
    if (typeof message !== "string" || message.trim().length < 10) {
      return res
        .status(400)
        .json({ error: "Message must be at least 10 characters" });
    }

    // Save the data
    const newMessage = new ContactUs({
      name: name.trim(),
      email: email.trim(),
      phone: phone.trim(),
      message: message.trim(),
    });

    await newMessage.save();

    res.status(201).json({
      message: "Contact form submitted successfully",
      contact: newMessage,
    });
  } catch (error) {
    console.error("Error submitting contact form:", error);
    res.status(500).json({ error: "Server error, please try again later." });
  }
};

// Delete Contact Us Message
export const deleteContactUs = async (req, res) => {
  try {
    const { contactId } = req.params;

    // Validate MongoDB ObjectId
    if (!mongoose.Types.ObjectId.isValid(contactId)) {
      return res.status(400).json({ error: "Invalid message ID" });
    }

    const deletedMessage = await ContactUs.findByIdAndDelete(contactId);

    if (!deletedMessage) {
      return res.status(404).json({ error: "Message not found" });
    }

    res.status(200).json({
      message: "Message deleted successfully",
      deleted: deletedMessage,
    });
  } catch (error) {
    console.error("Error deleting contact message:", error);
    res.status(500).json({ error: "Server error, please try again later." });
  }
};

// Get All Contact Us Messages
export const getAllContactUs = async (req, res) => {
  try {
    const messages = await ContactUs.find().sort({ submittedAt: -1 }); // sort latest first

    res.status(200).json({
      totalMessages: messages.length,
      messages,
    });
  } catch (error) {
    console.error("Error fetching contact messages:", error);
    res.status(500).json({ error: "Server error, please try again later." });
  }
};

export const updateContactUsStatus = async (req, res) => {
  try {
    const { contactId } = req.params;
    const { status } = req.body;

    // Validate contactId
    if (!mongoose.Types.ObjectId.isValid(contactId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid contact ID",
      });
    }

    // Find contact query
    const contactUs = await ContactUs.findById(contactId);
    if (!contactUs) {
      return res.status(404).json({
        success: false,
        message: "Contact query not found",
      });
    }

    // Validate status
    const validStatuses = ["pending", "resolved"];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        message: `Invalid status. Allowed: ${validStatuses.join(", ")}`,
      });
    }

    // Once resolve do not make it pending
    if (contactUs.status === "resolved" && status === "pending") {
      return res.status(400).json({
        success: false,
        message: "Cannot change status from resolved back to pending.",
      });
    }

    // If already resolved
    if (contactUs.status === "resolved" && status === "resolved") {
      return res.status(400).json({
        success: false,
        message: "Query is already resolved.",
      });
    }

    //  Update status
    contactUs.status = status;
    await contactUs.save();

    return res.status(200).json({
      success: true,
      message: "Status updated successfully",
      data: contactUs,
    });
  } catch (error) {
    console.error("Error updating contact status:", error);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};
