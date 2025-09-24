import nodemailer from "nodemailer";

export default async function handler(req, res) {
  // Only allow POST requests
  if (req.method !== "POST") {
    return res.status(405).json({ 
      success: false,
      error: "Method not allowed",
      message: "This endpoint only accepts POST requests"
    });
  }

  const { name, email, feedback } = req.body;

  // Validate required fields
  if (!name?.trim() || !email?.trim() || !feedback?.trim()) {
    return res.status(400).json({ 
      success: false,
      error: "Validation failed",
      message: "All fields (name, email, feedback) are required and cannot be empty"
    });
  }

  // Basic email validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email.trim())) {
    return res.status(400).json({
      success: false,
      error: "Invalid email format",
      message: "Please provide a valid email address"
    });
  }

  try {
    // Create transporter with enhanced configuration
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: parseInt(process.env.EMAIL_PORT) || 587,
      secure: process.env.EMAIL_PORT === "465", // true for 465, false for other ports
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
      tls: {
        rejectUnauthorized: false,
      },
    });

    // Verify connection configuration
    await transporter.verify();

    // Professional HTML email template
    const htmlContent = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>New Feedback Submission</title>
      </head>
      <body style="margin: 0; padding: 0; background-color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;">
        <div style="max-width: 600px; margin: 40px auto; background-color: #ffffff; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06); overflow: hidden;">
          
          <!-- Header -->
          <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px 40px; text-align: center;">
            <h1 style="margin: 0; color: #ffffff; font-size: 24px; font-weight: 600; letter-spacing: -0.025em;">
              New Feedback Received
            </h1>
            <p style="margin: 8px 0 0 0; color: rgba(255, 255, 255, 0.9); font-size: 14px;">
              ${new Date().toLocaleDateString('en-US', { 
                weekday: 'long', 
                year: 'numeric', 
                month: 'long', 
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
              })}
            </p>
          </div>

          <!-- Content -->
          <div style="padding: 40px;">
            <!-- Contact Information -->
            <div style="margin-bottom: 32px;">
              <h2 style="margin: 0 0 20px 0; color: #1f2937; font-size: 18px; font-weight: 600; border-bottom: 2px solid #e5e7eb; padding-bottom: 8px;">
                Contact Information
              </h2>
              
              <div style="display: flex; flex-direction: column; gap: 12px;">
                <div style="display: flex; align-items: center; padding: 12px; background-color: #f9fafb; border-radius: 8px; border-left: 4px solid #6366f1;">
                  <span style="font-weight: 600; color: #374151; margin-right: 8px; min-width: 50px;">Name:</span>
                  <span style="color: #1f2937;">${name.trim()}</span>
                </div>
                
                <div style="display: flex; align-items: center; padding: 12px; background-color: #f9fafb; border-radius: 8px; border-left: 4px solid #059669;">
                  <span style="font-weight: 600; color: #374151; margin-right: 8px; min-width: 50px;">Email:</span>
                  <a href="mailto:${email.trim()}" style="color: #059669; text-decoration: none;">${email.trim()}</a>
                </div>
              </div>
            </div>

            <!-- Feedback Content -->
            <div style="margin-bottom: 32px;">
              <h2 style="margin: 0 0 20px 0; color: #1f2937; font-size: 18px; font-weight: 600; border-bottom: 2px solid #e5e7eb; padding-bottom: 8px;">
                Feedback Message
              </h2>
              
              <div style="padding: 20px; background-color: #f8fafc; border-radius: 8px; border: 1px solid #e5e7eb;">
                <p style="margin: 0; color: #374151; line-height: 1.6; white-space: pre-wrap; font-size: 15px;">
${feedback.trim()}
                </p>
              </div>
            </div>

            <!-- Action Buttons -->
            <div style="text-align: center; margin-bottom: 20px;">
              <a href="mailto:${email.trim()}?subject=Re: Your Feedback" 
                 style="display: inline-block; background-color: #6366f1; color: #ffffff; text-decoration: none; padding: 12px 24px; border-radius: 8px; font-weight: 600; font-size: 14px; margin-right: 12px;">
                Reply to Sender
              </a>
            </div>
          </div>

          <!-- Footer -->
          <div style="background-color: #f9fafb; padding: 20px 40px; border-top: 1px solid #e5e7eb; text-align: center;">
            <p style="margin: 0; color: #6b7280; font-size: 12px; line-height: 1.5;">
              This message was sent automatically from your website's feedback form.<br>
              <strong>Submission ID:</strong> ${Date.now().toString(36).toUpperCase()}
            </p>
          </div>
        </div>
      </body>
      </html>
    `;

    // Plain text version for better compatibility
    const textContent = `
NEW FEEDBACK SUBMISSION
${new Date().toLocaleString()}

CONTACT INFORMATION
Name: ${name.trim()}
Email: ${email.trim()}

FEEDBACK MESSAGE
${feedback.trim()}

---
This message was sent from your website's feedback form.
Submission ID: ${Date.now().toString(36).toUpperCase()}
    `;

    // Send email with enhanced options
    const mailOptions = {
      from: {
        name: process.env.EMAIL_FROM_NAME || "Website Feedback",
        address: process.env.EMAIL_USER
      },
      to: process.env.FEEDBACK_RECEIVER_EMAIL,
      replyTo: email.trim(),
      subject: `New Feedback: ${name.trim()} - ${feedback.trim().substring(0, 50)}${feedback.trim().length > 50 ? '...' : ''}`,
      text: textContent,
      html: htmlContent,
      priority: 'normal',
      headers: {
        'X-Feedback-Source': 'Website Contact Form',
        'X-Sender-IP': req.headers['x-forwarded-for'] || req.connection?.remoteAddress || 'unknown'
      }
    };

    const info = await transporter.sendMail(mailOptions);

    console.log('Feedback email sent successfully:', {
      messageId: info.messageId,
      from: name.trim(),
      email: email.trim(),
      timestamp: new Date().toISOString()
    });

    return res.status(200).json({ 
      success: true,
      message: "Thank you for your feedback! We'll get back to you soon.",
      messageId: info.messageId
    });

  } catch (error) {
    console.error('Feedback submission error:', {
      error: error.message,
      stack: error.stack,
      timestamp: new Date().toISOString(),
      sender: email?.trim() || 'unknown'
    });

    // Return appropriate error response
    if (error.code === 'EAUTH') {
      return res.status(500).json({
        success: false,
        error: "Email authentication failed",
        message: "There was an issue with our email service. Please try again later."
      });
    }

    if (error.code === 'ECONNECTION') {
      return res.status(500).json({
        success: false,
        error: "Email server connection failed", 
        message: "Unable to connect to email service. Please try again later."
      });
    }

    return res.status(500).json({
      success: false,
      error: "Email delivery failed",
      message: "We encountered an issue sending your feedback. Please try again or contact us directly."
    });
  }
} 