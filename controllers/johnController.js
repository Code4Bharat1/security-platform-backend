import { saveJohnResult } from "../models/JohnResult.js";
import md5 from "crypto-js/md5.js";
import sha1 from "crypto-js/sha1.js";
import sha256 from "crypto-js/sha256.js";

// Sample dictionary (expandable)
const wordlist = [
  "admin", "123456", "password", "letmein", "abc123", "hello123", "welcome", "qwerty"
];

export const crackHash = async (req, res) => {
  const { hash } = req.body;
  let found = null;

  for (const word of wordlist) {
    const hashes = {
      MD5: md5(word).toString(),
      SHA1: sha1(word).toString(),
      SHA256: sha256(word).toString()
    };

    for (const [algo, generated] of Object.entries(hashes)) {
      if (hash === generated) {
        found = {
          algorithm: algo,
          password: word
        };
        break;
      }
    }
    if (found) break;
  }

  let result = found
    ? `🔓 Hash cracked!\nAlgorithm: ${found.algorithm}\nPassword: ${found.password}`
    : "❌ Unable to crack the hash with current wordlist.";

  await saveJohnResult({ hash, result });

  res.json({ success: true, result });
};
