import jwt from 'jsonwebtoken';
import User from '../models/user.js';
import bcrypt from 'bcryptjs';

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

// ✅ Inspect Token controller
export const inspectToken = async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: "Token not provided" });

    const decoded = jwt.decode(token, { complete: true });

    if (!decoded) {
      return res.status(400).json({ error: "Invalid token or cannot decode" });
    }

    const payload = decoded.payload;
    const issues = [];

    if (!payload.exp) issues.push("⚠️ Token missing expiration (exp) claim");
    if (payload.exp && Date.now() >= payload.exp * 1000) issues.push("❌ Token has expired");
    if (!payload.iss) issues.push("⚠️ Token missing issuer (iss) claim");
    if (!payload.sub) issues.push("⚠️ Token missing subject (sub) claim");
    if (!payload.iat) issues.push("⚠️ Token missing issued-at (iat) claim");

    res.json({ payload, issues });
  } catch (error) {
    console.error("Token inspect error:", error);
    res.status(500).json({ error: "Failed to analyze token" });
  }
};
