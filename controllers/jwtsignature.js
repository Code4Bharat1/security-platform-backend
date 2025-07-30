import jwt from "jsonwebtoken";
import JWTSignature from "../models/jwtsignature.model.js";

export const validateJWT = async (req, res) => {
  console.log("=== JWT VALIDATION DEBUG ===");
  console.log("Full request body:", JSON.stringify(req.body, null, 2));

  const { token, secret } = req.body;

  // Input validation
  if (!token || !secret) {
    console.log("❌ Missing token or secret");
    return res.status(400).json({ error: "Token and secret are required" });
  }
           
  // Trim whitespace
  const cleanToken = token.trim();
  const cleanSecret = secret.trim();

  console.log("🔍 Token length:", cleanToken.length);
  console.log("🔍 Secret:", cleanSecret);
  console.log(
    "🔍 Token (first 50 chars):",
    cleanToken.substring(0, 50) + "..."
  );
  console.log("🔍 Token parts count:", cleanToken.split(".").length);

  // Basic JWT format validation
  if (!cleanToken.includes(".")) {
    console.log("❌ Invalid JWT format - no dots found");
    return res
      .status(400)
      .json({
        error: "Invalid JWT format. JWT should have 3 parts separated by dots.",
      });
  }

  const tokenParts = cleanToken.split(".");
  if (tokenParts.length !== 3) {
    console.log(
      "❌ Invalid JWT format - found",
      tokenParts.length,
      "parts instead of 3"
    );
    return res
      .status(400)
      .json({
        error: `Invalid JWT format. Found ${tokenParts.length} parts, expected 3. ${score} `,
      });
  }

  // Test with jwt.io standard token first
  console.log("🧪 Testing with known working token...");
  const testToken =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
  const testSecret = "your-256-bit-secret";

  try {
    const testResult = jwt.verify(testToken, testSecret, { complete: true });
    console.log("✅ Test token validation successful");
  } catch (testErr) {
    console.log("❌ Test token failed:", testErr.message);
  }

  // Now try the actual token
  try {
    console.log("🔐 Attempting to verify actual token...");

    // Try without complete: true first
    const decoded = jwt.verify(cleanToken, cleanSecret, { complete: true });

    console.log("✅ JWT verification successful!");
    console.log("Header:", JSON.stringify(decoded.header, null, 2));
    console.log("Payload:", JSON.stringify(decoded.payload, null, 2));

    const { header, payload } = decoded;

    // Save successful validation attempt in DB
    try {
      const log = new JWTSignature({
        token: cleanToken,
        secret: cleanSecret,
        valid: true,
        header,
        payload,
      });
      await log.save();
      console.log("✅ Saved to database successfully");
    } catch (dbError) {
      console.error("⚠️ Database save error:", dbError.message);
      // Continue execution even if DB save fails
    }

    return res.json({
      message: "JWT signature is valid",
      header,
      payload,
    });
  } catch (err) {
    console.error("❌ JWT validation error details:");
    console.error("Error name:", err.name);
    console.error("Error message:", err.message);
    console.error("Full error:", err);

    // Try to decode without verification to see the token content
    try {
      const decoded = jwt.decode(cleanToken, { complete: true });
      // console.log("🔍 Token decoded without verification:");
      // console.log("Header:", JSON.stringify(decoded.header, null, 2));
      // .log("Payload:", JSON.stringify(decoded.payload, null, 2));
    } catch (decodeErr) {
      console.error("❌ Cannot even decode token:", decodeErr.message);
    }

    // Save failed validation attempt in DB
    try {
      const log = new JWTSignature({
        token: cleanToken,
        secret: cleanSecret,
        valid: false,
      });
      await log.save();
    } catch (dbError) {
      console.error("⚠️ Database save error:", dbError.message);
    }

    // Provide more specific error messages
    let errorMessage = "Invalid JWT signature or token";

    if (err.name === "TokenExpiredError") {
      errorMessage = "JWT token has expired";
    } else if (err.name === "JsonWebTokenError") {
      if (err.message.includes("invalid signature")) {
        errorMessage = "Invalid JWT signature - check your secret key";
      } else if (err.message.includes("malformed")) {
        errorMessage = "Malformed JWT token";
      } else {
        errorMessage = `JWT Error: ${err.message}`;
      }
    } else if (err.name === "NotBeforeError") {
      errorMessage = "JWT token is not active yet";
    }

    return res.status(400).json({ error: errorMessage });
  }
};
