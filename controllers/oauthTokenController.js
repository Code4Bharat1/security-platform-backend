import OAuthToken from "../models/OAuthToken.js";
import jwt from "jsonwebtoken";

// Analyze decoded token payload
function analyzePayload(payload) {
  const issues = [];

  if (!payload || typeof payload !== "object") {
    issues.push("Payload is not a valid object.");
    return issues;
  }

  if (!payload.iss) issues.push("Issuer (iss) claim missing.");
  if (!payload.exp) issues.push("Expiration (exp) claim missing.");
  else if (Date.now() >= payload.exp * 1000) issues.push("Token has expired.");

  if (payload.admin === true) issues.push("Token has admin privileges.");

  return issues;
}

export async function getAllTokens(req, res) {
  try {
    const tokens = await OAuthToken.find().sort({ _id: -1 }); // latest first
    return res.json(tokens);
  } catch (error) {
    console.error('getAllTokens error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
}


export async function inspectToken(req, res) {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ error: "Token is required" });
    }

    // Remove extra spaces, newlines, etc.
    const cleanToken = token.replace(/\s+/g, "");

    let payload = null;
    let issues = [];

    try {
      const decoded = jwt.decode(cleanToken, { complete: false });

      if (decoded && typeof decoded === "object") {
        payload = decoded;
        issues = analyzePayload(payload);
      } else {
        payload = { raw: cleanToken };
        issues.push("Token is not a valid JWT format.");
      }
    } catch (err) {
      payload = { raw: cleanToken };
      issues.push("Token decoding failed: " + err.message);
    }

    // Save to database
    await OAuthToken.create({ token: cleanToken, payload, issues });

    return res.json({ payload, issues });
  } catch (error) {
    console.error("inspectToken error:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
}
