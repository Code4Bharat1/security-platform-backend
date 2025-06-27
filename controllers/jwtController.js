import jwt from "jsonwebtoken";
import JwtToken from "../models/JwtToken.js";
export const saveToken = async (req, res) => {
  try {
    const { token, secret } = req.body;

    if (!token) {
      return res.status(400).json({ error: "Token is required" });
    }

    // Optionally verify token with secret
    if (secret) {
      try {
        jwt.verify(token, secret);
      } catch (err) {
        return res.status(400).json({ error: "Invalid token or secret" });
      }
    }

    const savedToken = new JwtToken({ token, secret });
    await savedToken.save();

    res.status(201).json({ message: "Token saved", data: savedToken });
  } 
  
 catch (error) {
    console.error(" Error saving JWT token:", error); 
    res.status(500).json({ error: error.message });
  }
};

export const getAllTokens = async (req, res) => {
  try {
    const tokens = await JwtToken.find();
    res.json(tokens);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};
