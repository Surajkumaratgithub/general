import { transporter } from "../utils/emailTransporter.js";
import dotenv from "dotenv";
import formatUserData from "../utils/formatInput.js";

dotenv.config();

export const sendPasswordToEmail = async (user) => {
  try {
    console.log(user);

    const { email, name, role, password } = formatUserData(user);

    const htmlContent = `
      <p>Hello <strong>${name.firstName}</strong>,</p>
      <p>Your <strong>${role}</strong> account has been successfully created in the <strong>LMS system</strong>.</p>
      <p><strong>Here are your login credentials:</strong></p>
      <ul>
        <li><strong>Email:</strong> ${email}</li>
        <li><strong>Temporary Password:</strong> ${password}</li>
      </ul>
      <p>Please log in using the above credentials and <strong>change your password</strong> immediately after your first login for security purposes.</p>
      <p>👉 <a href="${process.env.BASE_URL}/login">Click here to login</a></p>
      <p>Thank you,<br>Webseeder Team</p>
    `;

    const mailOptions = {
      from: `"Webseeder" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: `Your ${role} Account creation`,
      html: htmlContent,
    };

    const response = await transporter.sendMail(mailOptions);
    console.log(response);

    return response.accepted.length > 0;
  } catch (error) {
    console.error("Error sending email:", error.message);
    throw new Error("Error sending email: " + error.message);
  }
};
