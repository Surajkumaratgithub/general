import multer from "multer";

// Set up memory storage for multer
const storage = multer.memoryStorage(); // Store files in memory for easy access

// Define the upload limits and file handling
const upload = multer({
  storage,
  limits: {
    fileSize: 50 * 1024 * 1024, // Limit file size to 50MB
  },
});

export default upload;
