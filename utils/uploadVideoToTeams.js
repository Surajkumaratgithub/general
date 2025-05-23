import { Client } from "@microsoft/microsoft-graph-client";
import "isomorphic-fetch";
import dotenv from "dotenv";

dotenv.config();

// Function to get an authenticated Graph client
const getAuthenticatedClient = async () => {
  const tokenResponse = await fetch(
    `https://login.microsoftonline.com/${process.env.TENANT_ID}/oauth2/v2.0/token`,
    {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: process.env.CLIENT_ID,
        scope: "https://graph.microsoft.com/.default",
        client_secret: process.env.CLIENT_SECRET,
        grant_type: "client_credentials",
      }),
    }
  );
  const tokenData = await tokenResponse.json();
  const accessToken = tokenData.access_token;

  return Client.init({
    authProvider: (done) => {
      done(null, accessToken);
    },
  });
};

// Function to upload video to Teams storage (OneDrive)
const uploadToTeams = async (videoBuffer, fileName) => {
  try {
    const client = await getAuthenticatedClient();
    // Upload to OneDrive under a 'Teachers/Videos' folder
    const driveItem = await client
      .api("/me/drive/root:/Teachers/Videos:/children")
      .post({
        "@microsoft.graph.conflictBehavior": "rename",
        name: fileName,
        file: {},
      });
    const uploadSession = await client
      .api(`/me/drive/items/${driveItem.id}/createUploadSession`)
      .post({});
    const uploadUrl = uploadSession.uploadUrl;

    // Upload the video buffer
    const response = await fetch(uploadUrl, {
      method: "PUT",
      body: videoBuffer,
    });
    const uploadedItem = await response.json();
    return uploadedItem.webUrl; // Return the URL to the video
  } catch (error) {
    console.error("Microsoft Teams Upload Error:", error);
    throw new Error("Failed to upload video to Microsoft Teams storage");
  }
};

export default uploadToTeams;
