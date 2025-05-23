import cloudinary from "cloudinary";
import dotenv from "dotenv";

dotenv.config();

// Configure Cloudinary with environment variables
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Function to upload base64 string to Cloudinary
const uploadImageToCloudinary = async (base64String, folderName) => {
  try {
    const result = await cloudinary.uploader.upload(base64String, {
      folder: folderName, // Organize in a folder
      transformation: [{ width: 500, height: 500, crop: "limit" }], // Optional: resize image
    });
    return result.secure_url; // Return the secure URL
  } catch (error) {
    console.error("Cloudinary Upload Error:", error);
    throw new Error("Failed to upload photo to Cloudinary");
  }
};

export default uploadImageToCloudinary;
