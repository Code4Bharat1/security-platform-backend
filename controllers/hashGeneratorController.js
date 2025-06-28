import crypto from "crypto";

export const generateHash = (req, res) => {
  const { text, algorithm } = req.body;

  if (!text || !algorithm) {
    return res.status(400).json({ error: "Text and algorithm are required." });
  }

  try {
    const hash = crypto.createHash(algorithm).update(text).digest("hex");
    res.json({ hash });
  } catch (err) {
    res.status(500).json({ error: "Invalid hashing algorithm." });
  }
};
