import upload from "../config/multerConfig.js";

// Define the fields for the form-data (the file inputs you expect from the client)
const uploadMiddleware = upload.fields([
  { name: "resume", maxCount: 1 }, // Expecting a single resume file
  { name: "videoConsent", maxCount: 1 }, // Expecting a single video consent file
]);

export default uploadMiddleware;
