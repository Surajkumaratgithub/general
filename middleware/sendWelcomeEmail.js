import dotenv from "dotenv";
import formatUserData from "../utils/formatInput.js";
import { transporter } from "../utils/emailTransporter.js";

const BASE_URL = process.env.BASE_URL;
dotenv.config();

const sendWelcomeEmail = async (req, res, next) => {
  try {
    // Assuming req.user is set after successful registration in the controller
    const { email, name } = formatUserData(req.body);

    // HTML email template
    const htmlContent = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0; }
        .container { max-width: 600px; margin: 20px auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        .header { background-color: #1E88E5; padding: 20px; text-align: center; color: white; }
        .header h1 { margin: 0; font-size: 24px; }
        .content { padding: 20px; }
        .content h2 { color: #333; }
        .content p { color: #666; line-height: 1.6; }
        .highlight { color: #1E88E5; font-weight: bold; }
        .cta-button { display: inline-block; padding: 10px 20px; margin: 20px 0; background-color: #1E88E5; color: white; text-decoration: none; border-radius: 5px; }
        .footer { background-color: #f4f4f4; padding: 10px; text-align: center; color: #999; font-size: 12px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>Welcome to Webseeder</h1>
        </div>
        <div class="content">
          <h2>Dear ${name.firstName},</h2>
          <p>On behalf of <span class="highlight">Webseeder</span>, we extend our heartfelt gratitude for choosing us as your partner in your educational journey. Your decision to join our esteemed institute marks the beginning of an inspiring path toward mastering <span class="highlight">music, chess, and dance</span>.</p>
          <p>At Webseeder, we pride ourselves on delivering world-class learning experiences, crafted by dedicated instructors who are leaders in their fields. Our institute is built on a foundation of trust, excellence, and a passion for nurturing talent. Whether you're exploring the rhythms of music, the strategies of chess, or the grace of dance, we are committed to empowering you with the skills and confidence to shine.</p>
          <p>We invite you to dive into our carefully designed courses and discover the joy of learning with a community that values your growth. With Webseeder by your side, your potential is limitless.</p>
          <a href="${BASE_URL}/courses" class="cta-button">Start Your Journey</a>
          <p>Should you have any questions or need guidance, our dedicated support team is here for you at <a href="mailto:support@Webseederinstitute.com">support@Webseederinstitute.com</a>. We look forward to celebrating your achievements and being a trusted part of your learning adventure.</p>
          <p>With warmest thanks and best wishes,<br>
          The Webseeder Team</p>
        </div>
        <div class="footer">
          <p>© 2025 Webseeder. All rights reserved.</p>
          <p><a href="${BASE_URL}/unsubscribe">Unsubscribe</a></p>
        </div>
      </div>
    </body>
    </html>
  `;

    // Email options
    const mailOptions = {
      from: `"Webseeder Institute" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Welcome to Webseeder Institute – Thank You for Trusting Us!",
      html: htmlContent,
    };
    console.log("mail options", mailOptions);
    // Send the email
    await transporter.sendMail(mailOptions);
    console.log("email sent");
    next(); // Proceed to the next middleware/response
  } catch (error) {
    console.error("Error sending welcome email:", error);
    // Don't block the response; log the error and proceed
    next();
  }
};

export default sendWelcomeEmail;
