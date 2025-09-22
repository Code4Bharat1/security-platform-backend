import nodemailer from "nodemailer";

export default async function handler(req, res) {
  if (req.method !== "POST")
    return res.status(405).json({ error: "Method not allowed" });

  const { name, email, feedback } = req.body;

  if (!name || !email || !feedback) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: process.env.EMAIL_PORT || 587,
      secure: false,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
      tls: {
        rejectUnauthorized: false, // prevents certificate errors
      },
    });

    const htmlContent = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.05);">
        <h2 style="color: #4F46E5; margin-bottom: 15px;">💬 New Feedback Received</h2>
        <p><strong>Name:</strong> ${name}</p>
        <p><strong>Email:</strong> ${email}</p>
        <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;" />
        <p style="white-space: pre-wrap;"><strong>Feedback:</strong><br/>${feedback}</p>
        <p style="color: #555; font-size: 0.85rem; margin-top: 20px;">Sent from your website feedback form.</p>
      </div>
    `;

    await transporter.sendMail({
      from: `"Feedback Form" <${process.env.EMAIL_USER}>`,
      to: process.env.FEEDBACK_RECEIVER_EMAIL,
      subject: `New Feedback from ${name}`,
      text: `Name: ${name}\nEmail: ${email}\nFeedback:\n${feedback}`,
      html: htmlContent,
    });

    res.status(200).json({ message: "Feedback sent successfully!" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to send feedback" });
  }
}
