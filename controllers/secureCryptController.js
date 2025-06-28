import CryptoJS from "crypto-js";
import { saveSecureCryptResult } from "../models/SecureCryptResult.js";

const secretKey = "SuperSecretKey123!"; // can be env variable

export const encryptText = async (req, res) => {
  const { text } = req.body;

  if (!text) return res.status(400).json({ error: "Text is required" });

  const encrypted = CryptoJS.AES.encrypt(text, secretKey).toString();

  await saveSecureCryptResult({ type: "encrypt", input: text, output: encrypted });

  res.json({ success: true, encrypted });
};

export const decryptText = async (req, res) => {
  const { encryptedText } = req.body;

  if (!encryptedText) return res.status(400).json({ error: "Encrypted text is required" });

  let decrypted = null;
  try {
    const bytes = CryptoJS.AES.decrypt(encryptedText, secretKey);
    decrypted = bytes.toString(CryptoJS.enc.Utf8);
  } catch (err) {
    return res.status(500).json({ error: "Failed to decrypt text." });
  }

  await saveSecureCryptResult({ type: "decrypt", input: encryptedText, output: decrypted });

  res.json({ success: true, decrypted });
};
