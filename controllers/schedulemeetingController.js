// pages/api/schedule.js
import nodemailer from "nodemailer";

export default async function schedulemetting(req, res) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  try {
    const { meetingData } = req.body;
    if (!meetingData) return res.status(400).json({ error: "Missing meetingData" });

    const {
      title = "Untitled Meeting",
      agenda = "",
      selectedDate,
      selectedTime,
      duration,
      type,
      venue,
      participants = [],
      hostName,
      hostEmail,
      contactNumber,
    } = meetingData;

    if (!hostEmail || !selectedDate || !selectedTime) {
      return res.status(400).json({ error: "Host email, date and time are required" });
    }

    // Create transporter using SMTP details from environment variables
    // .env: SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_SECURE (true/false), SMTP_FROM, ADMIN_EMAIL
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: parseInt(process.env.EMAIL_PORT || "587", 10),
      // true for 465, false for other ports
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const fromAddress = process.env.SMTP_FROM || process.env.EMAIL_USER;
    const adminEmail = process.env.FEEDBACK_RECEIVER_EMAIL;

    // Plain text and HTML for user
    const userSubject = `Meeting confirmed: ${title} — ${selectedDate} ${selectedTime}`;
    const userText = `
Hi ${hostName || ""},

Your meeting has been scheduled.

Title: ${title}
Agenda: ${agenda}
Date: ${selectedDate}
Time: ${selectedTime}
Duration: ${duration} minutes
Type: ${type}
Venue/Link: ${venue}
Contact: ${contactNumber}

Participants: ${participants && participants.length ? participants.join(", ") : "None listed"}

If you need to change or cancel, please visit the app.

Thanks,
Your App Team
`.trim();

    const userHtml = `
      <div style="font-family: system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial;">
        <h2>Meeting confirmed</h2>
        <p><strong>${title}</strong></p>
        <p>${agenda || ""}</p>
        <table cellspacing="0" cellpadding="6">
          <tr><td><strong>Date:</strong></td><td>${selectedDate}</td></tr>
          <tr><td><strong>Time:</strong></td><td>${selectedTime}</td></tr>
          <tr><td><strong>Duration:</strong></td><td>${duration} minutes</td></tr>
          <tr><td><strong>Type:</strong></td><td>${type}</td></tr>
          <tr><td><strong>Venue/Link:</strong></td><td>${venue || "-"}</td></tr>
          <tr><td><strong>Contact:</strong></td><td>${contactNumber || "-"}</td></tr>
          <tr><td><strong>Participants:</strong></td><td>${participants && participants.length ? participants.join(", ") : "None"}</td></tr>
        </table>
        <p>Thanks,<br/>Your App Team</p>
      </div>
    `;

    // send to user (registered email)
    await transporter.sendMail({
      from: fromAddress,
      to: hostEmail,
      subject: userSubject,
      text: userText,
      html: userHtml,
    });

    // Notify admin (if configured)
    if (adminEmail) {
      const adminSubject = `New meeting scheduled by ${hostName || hostEmail}: ${title}`;
      const adminText = `
Admin,

User (${hostName || hostEmail}) scheduled a meeting.

Title: ${title}
Date: ${selectedDate}
Time: ${selectedTime}
Duration: ${duration} minutes
Venue: ${venue || "-"}

Participants: ${participants && participants.length ? participants.join(", ") : "None"}

`;
      const adminHtml = `
        <div>
          <h3>New meeting scheduled</h3>
          <p><strong>User:</strong> ${hostName || hostEmail}</p>
          <p><strong>Title:</strong> ${title}</p>
          <p><strong>Date / Time:</strong> ${selectedDate} ${selectedTime}</p>
          <p><strong>Venue:</strong> ${venue || "-"}</p>
          <p><strong>Participants:</strong> ${participants && participants.length ? participants.join(", ") : "None"}</p>
        </div>
      `;

      await transporter.sendMail({
        from: fromAddress,
        to: adminEmail,
        subject: adminSubject,
        text: adminText,
        html: adminHtml,
      });
    }

    // Optionally: send invites to participants (uncomment to enable)
    // const validParticipants = (participants || []).filter(Boolean);
    // if (validParticipants.length > 0) {
    //   const participantSubject = `You're invited: ${title} — ${selectedDate} ${selectedTime}`;
    //   for (const p of validParticipants) {
    //     await transporter.sendMail({
    //       from: fromAddress,
    //       to: p,
    //       subject: participantSubject,
    //       text: userText,
    //       html: userHtml,
    //     });
    //   }
    // }

    // Return success and savedMeeting (client uses savedMeeting to push into local list)
    const savedMeeting = { ...meetingData, id: Date.now() };
    return res.status(200).json({ message: "Emails sent", savedMeeting });
  } catch (err) {
    console.error("Error in /api/schedule:", err);
    return res.status(500).json({ error: "Failed to send emails" });
  }
}
