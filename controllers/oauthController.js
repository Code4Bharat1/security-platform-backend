// controllers/auth.controller.js (excerpt)
import jwt from "jsonwebtoken";
import User from "../models/user.js";
import bcrypt from "bcryptjs";

// ... signup, login unchanged ...
// ✅ Signup controller
export const signup = async (req, res) => {
  try {
    const { email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await User.create({ email, password: hashedPassword });

    res.status(201).json({ message: "User created", user: newUser });
  } catch (error) {
    console.error("Signup error:", error);
    res.status(500).json({ message: "Signup failed" });
  }
};

// ✅ Login controller
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid password" });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.status(200).json({ message: "Login successful", token, user });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Login failed" });
  }
};


export const inspectToken = async (req, res) => {
  try {
    const { token, secret } = req.body; // secret is optional – used to verify signature
    if (!token) return res.status(400).json({ error: "Token not provided" });

    const decoded = jwt.decode(token, { complete: true });
    if (!decoded) return res.status(400).json({ error: "Invalid token or cannot decode" });

    const header = decoded.header || {};
    const payload = decoded.payload || {};
    const nowSec = Math.floor(Date.now() / 1000);

    // ------ Lifetime & meta ------
    const exp = Number.isFinite(payload.exp) ? payload.exp : null;
    const iat = Number.isFinite(payload.iat) ? payload.iat : null;
    const nbf = Number.isFinite(payload.nbf) ? payload.nbf : null;

    const isExpired = exp != null ? nowSec >= exp : null;
    const expiresInSeconds = exp != null ? exp - nowSec : null;
    const issuedAgoSeconds = iat != null ? nowSec - iat : null;

    let lifetimeSeconds = null;
    let lifetimePercentUsed = null;
    if (exp != null && iat != null && exp > iat) {
      lifetimeSeconds = exp - iat;
      const used = Math.min(Math.max(nowSec - iat, 0), lifetimeSeconds);
      lifetimePercentUsed = +( (used / lifetimeSeconds) * 100 ).toFixed(2);
    }

    // ------ Issues ------
    const issues = [];
    if (!payload.exp) issues.push("⚠️ Token missing expiration (exp) claim");
    if (isExpired === true) issues.push("❌ Token has expired");
    if (!payload.iss) issues.push("⚠️ Token missing issuer (iss) claim");
    if (!payload.sub) issues.push("⚠️ Token missing subject (sub) claim");
    if (!payload.iat) issues.push("⚠️ Token missing issued-at (iat) claim");
    if (header.alg && String(header.alg).toLowerCase() === "none") {
      issues.push("❌ Insecure algorithm (alg: none)");
    }
    if (exp != null && iat != null && exp - iat > 60 * 60 * 24 * 7) {
      issues.push("⚠️ Token lifetime is longer than 7 days");
    }

    // ------ Optional signature verification ------
    let signatureVerified = null; // null = not attempted
    if (secret && header.alg && String(header.alg).toLowerCase() !== "none") {
      try {
        // Enforce token's declared alg to avoid alg-confusion
        jwt.verify(token, secret, { algorithms: [header.alg], ignoreExpiration: true });
        signatureVerified = true;
      } catch (e) {
        signatureVerified = false;
        issues.push(`❌ Signature verification failed: ${e.message}`);
      }
    }

    // ------ Security score (0–100) ------
    let score = 100;
    const breakdown = [];

    const add = (label, delta, status) => {
      score += delta; // delta is negative for penalties
      breakdown.push({ label, delta, status });
    };

    // Signature
    if (signatureVerified === false) add("Signature invalid", -40, "fail");
    else if (signatureVerified === null) add("Signature not verified", -15, "warn");
    else add("Signature valid", 0, "ok");

    // Expiry
    if (!payload.exp) add("Missing exp", -25, "warn");
    else if (isExpired) add("Token expired", -35, "fail");
    else add("Has exp", 0, "ok");

    // Standard claims
    if (!payload.iss) add("Missing iss", -10, "warn");
    if (!payload.sub) add("Missing sub", -5, "warn");
    if (!payload.iat) add("Missing iat", -5, "warn");
    if (!payload.aud) add("Missing aud", -5, "warn");

    // Lifetime too long
    if (exp != null && iat != null && exp - iat > 60 * 60 * 24 * 7) {
      add("Lifetime > 7d", -10, "warn");
    }

    // alg none
    if (header.alg && String(header.alg).toLowerCase() === "none") {
      add("alg: none", -50, "fail");
    }

    score = Math.max(0, Math.min(100, score));

    return res.json({
      success: true,
      header,
      payload,
      issues,
      meta: {
        alg: header.alg || null,
        nowEpoch: nowSec,
        iatEpoch: iat,
        expEpoch: exp,
        nbfEpoch: nbf,
        iatHuman: iat != null ? new Date(iat * 1000).toISOString() : null,
        expHuman: exp != null ? new Date(exp * 1000).toISOString() : null,
        nbfHuman: nbf != null ? new Date(nbf * 1000).toISOString() : null,
        isExpired,
        expiresInSeconds,
        issuedAgoSeconds,
        lifetimeSeconds,
        lifetimePercentUsed,
        signatureVerified,
        securityScore: score,
        scoreBreakdown: breakdown,
      },
    });
  } catch (error) {
    console.error("Token inspect error:", error);
    res.status(500).json({ error: "Failed to analyze token" });
  }
};
