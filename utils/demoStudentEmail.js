import { transporter } from "./emailTransporter.js";


export const sendDemoWelcomeEmail = async ({ to, name }) => {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to,
    subject: "Welcome to Your Demo Session!",
    html: `
      <h2>Hello ${name.firstName} ${name.lastName},</h2>
      <p>Thank you for registering for a demo session.</p>
      <p>We'll be in touch with more details soon.</p>
      <p>Best regards,<br/>Demo Team</p>
    `,
  };

  await transporter.sendMail(mailOptions);
};