// stupiod you donot work one think i only want that you upload the pdf in cludinary and give me the url of pdf to view the pdf online
import { v2 as cloudinary } from "cloudinary";
import dotenv from "dotenv";

dotenv.config();

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const uploadResumeToCloudinary = async (buffer, folderName) => {
  try {
    const result = await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream(
        {
          folder: folderName,
          resource_type: "auto",
        },
        (error, result) => {
          if (error) return reject(error);
          resolve(result);
        }
      );

      stream.end(buffer);
    });

    const downloadUrl = result.secure_url;

    return downloadUrl;
  } catch (error) {
    console.error("Cloudinary Resume Upload Error:", error);
    throw new Error("Failed to upload resume to Cloudinary.");
  }
};

export default uploadResumeToCloudinary;
