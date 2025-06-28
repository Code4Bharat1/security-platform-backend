import express from "express";
import crypto from "crypto";
import HashResult from "../models/HashResult.js";

const router = express.Router();

router.post("/hash-generator", async (req, res) => {
  const { text, algorithm } = req.body;

  if (!text || !algorithm) {
    return res.status(400).json({ error: "Text and algorithm are required." });
  }

  try {
    let hash;
    const algo = algorithm.toLowerCase();

    if (["sha256", "sha1", "md5"].includes(algo)) {
      hash = crypto.createHash(algo).update(text).digest("hex");
    } else {
      return res.status(400).json({ error: "Unsupported algorithm." });
    }

    // ✅ Save to database
    const saved = await new HashResult({ text, hash, algorithm }).save();

    res.json({ hash });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Hashing failed." });
  }
});

export default router;
