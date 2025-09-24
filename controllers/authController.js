import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import nodemailer from "nodemailer";
import User from "../models/user.js";
import { Otp } from '../models/otp.js';

// Nodemailer transporter
const transporter = nodemailer.createTransport({
  host: process.env.MAIL_HOST, // e.g., smtp.gmail.com
  port: +process.env.MAIL_PORT, // e.g., 587
  secure: process.env.MAIL_SECURE === 'true',
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS,
  },
});

// Generate access token
const generateToken = (user) => {
  return jwt.sign(
    { id: user._id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
  );
};

// Generate refresh token
const generateRefreshToken = async (user) => {
  const refreshToken = jwt.sign(
    { id: user._id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: '30d' }
  );
  user.refreshToken = refreshToken;
  await user.save();
  return refreshToken;
};

// Create audit log (mock implementation, adjust as needed)
const createAuditLog = async ({ adminId, adminName, actionType, description, targetType }) => {
  console.log(`Audit Log: ${adminName} (${adminId}) - ${actionType} - ${description} - ${targetType}`);
  // Implement actual audit logging if needed (e.g., save to a MongoDB collection)
};

// Signup controller
export const signup = async (req, res) => {
  try {
    const { email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await User.create({ email, password: hashedPassword, credits: 30 });

    res.status(201).json({ message: "User created", user: { id: newUser._id, email: newUser.email, credits: newUser.credits } });
  } catch (error) {
    console.error("Signup error:", error);
    res.status(500).json({ message: "Signup failed" });
  }
};

// Login controller
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid password" });

    const token = generateToken(user);
    const refreshToken = await generateRefreshToken(user);

    await createAuditLog({
      adminId: user._id,
      adminName: user.email,
      actionType: 'USER_LOGIN',
      description: `User ${user.email} logged in successfully`,
      targetType: 'System',
    });

    res.cookie('access_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 60 * 60 * 1000, // 1 hour
    });

    res.status(200).json({
      message: "Login successful",
      token,
      refreshToken,
      user: { id: user._id, email: user.email, credits: user.credits },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Login failed" });
  }
};

// Logout controller
export const logout = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (user) {
      user.refreshToken = null;
      await user.save();
    }

    res.clearCookie('access_token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    });

    res.status(200).json({ message: "Logged out" });
  } catch (error) {
    console.error("Logout error:", error);
    res.status(500).json({ message: "Logout failed" });
  }
};

// Refresh token controller
export const refreshAccessToken = async (req, res) => {
  const { refreshToken } = req.body;

  try {
    if (!refreshToken) {
      return res.status(401).json({ message: "No refresh token provided" });
    }

    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user || user.refreshToken !== refreshToken) {
      return res.status(401).json({ message: "Invalid or expired refresh token" });
    }

    const newAccessToken = generateToken(user);
    const newRefreshToken = await generateRefreshToken(user);

    res.status(200).json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    });
  } catch (error) {
    console.error("Refresh token error:", error);
    res.status(401).json({ message: "Invalid or expired refresh token" });
  }
};

// Forgot password controller
export const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Email not recognized" });
    }

    const otp = String(Math.floor(100000 + Math.random() * 900000));
    const expires = Date.now() + 10 * 60 * 1000; // 10 minutes

    await Otp.findOneAndUpdate(
      { email },
      { code: otp, expires, verified: false },
      { upsert: true }
    );

    await transporter.sendMail({
      from: `"Security Platform" <${process.env.MAIL_USER}>`,
      to: email,
      subject: "Password Reset OTP",
      text: `Your OTP is ${otp}. It expires in 10 minutes.`,
    });

    res.status(200).json({ message: "OTP sent" });
  } catch (error) {
    console.error("Forgot password error:", error);
    res.status(500).json({ message: "Failed to send OTP" });
  }
};

// Verify OTP controller
export const verifyOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;

    const record = await Otp.findOne({ email, code: otp });
    if (!record || record.code !== otp || record.expires < Date.now()) {
      return res.status(400).json({ message: "Invalid or expired OTP" });
    }

    record.verified = true;
    await record.save();

    res.status(200).json({ message: "OTP verified" });
  } catch (error) {
    console.error("Verify OTP error:", error);
    res.status(500).json({ message: "Failed to verify OTP" });
  }
};

// Reset password controller
export const resetPassword = async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;

    const record = await Otp.findOne({ email, code: otp, verified: true });
    if (!record || record.code !== otp || !record.verified) {
      return res.status(400).json({ message: "OTP not verified" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    await Otp.deleteOne({ email });

    res.status(200).json({ message: "Password has been reset" });
  } catch (error) {
    console.error("Reset password error:", error);
    res.status(500).json({ message: "Failed to reset password" });
  }
};

// Inspect token controller
export const inspectToken = async (req, res) => {
  try {
    const { token, secret } = req.body;
    if (!token) return res.status(400).json({ error: "Token not provided" });

    const decoded = jwt.decode(token, { complete: true });
    if (!decoded) return res.status(400).json({ error: "Invalid token or cannot decode" });

    const header = decoded.header || {};
    const payload = decoded.payload || {};
    const nowSec = Math.floor(Date.now() / 1000);

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
      lifetimePercentUsed = +((used / lifetimeSeconds) * 100).toFixed(2);
    }

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

    let signatureVerified = null;
    if (secret && header.alg && String(header.alg).toLowerCase() !== "none") {
      try {
        jwt.verify(token, secret, { algorithms: [header.alg], ignoreExpiration: true });
        signatureVerified = true;
      } catch (e) {
        signatureVerified = false;
        issues.push(`❌ Signature verification failed: ${e.message}`);
      }
    }

    let score = 100;
    const breakdown = [];

    const add = (label, delta, status) => {
      score += delta;
      breakdown.push({ label, delta, status });
    };

    if (signatureVerified === false) add("Signature invalid", -40, "fail");
    else if (signatureVerified === null) add("Signature not verified", -15, "warn");
    else add("Signature valid", 0, "ok");

    if (!payload.exp) add("Missing exp", -25, "warn");
    else if (isExpired) add("Token expired", -35, "fail");
    else add("Has exp", 0, "ok");

    if (!payload.iss) add("Missing iss", -10, "warn");
    if (!payload.sub) add("Missing sub", -5, "warn");
    if (!payload.iat) add("Missing iat", -5, "warn");
    if (!payload.aud) add("Missing aud", -5, "warn");

    if (exp != null && iat != null && exp - iat > 60 * 60 * 24 * 7) {
      add("Lifetime > 7d", -10, "warn");
    }

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

// Recharge credits controller
export const rechargeCredits = async (req, res) => {
  try {
    const { amount } = req.body;
    if (!amount || amount < 1) {
      return res.status(400).json({ message: "Invalid recharge amount" });
    }

    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    user.credits += amount;
    await user.save();

    res.status(200).json({
      message: "Credits recharged successfully",
      user: { id: user._id, email: user.email, credits: user.credits },
    });
  } catch (error) {
    console.error("Recharge credits error:", error);
    res.status(500).json({ message: "Recharge failed" });
  }
};