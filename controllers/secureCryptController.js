// controllers/secureCryptController.js
import crypto from "crypto";

const ALGO = "aes-256-gcm";
const KDF = "pbkdf2";
const KDF_HASH = "sha256";
const KEY_LEN = 32;              // 256-bit
const PBKDF2_ITER = 310000;      // OWASP recommends >= 210k for PBKDF2-SHA256 in 2025

const b64 = (buf) => Buffer.from(buf).toString("base64");
const ub64 = (str) => Buffer.from(str, "base64");

/**
 * Derive key from passphrase using PBKDF2, or accept a raw base64 key.
 */
function getKey({ passphrase, keyB64, salt }) {
  if (passphrase) {
    const key = crypto.pbkdf2Sync(
      passphrase,
      salt,
      PBKDF2_ITER,
      KEY_LEN,
      KDF_HASH
    );
    return key;
  }
  if (keyB64) {
    const key = ub64(keyB64);
    if (key.length !== KEY_LEN) throw new Error("INVALID_KEY_LENGTH");
    return key;
  }
  // Auto-generate a random key (returned to caller)
  return crypto.randomBytes(KEY_LEN);
}

export const encryptText = (req, res) => {
  try {
    const { text, passphrase, keyB64 } = req.body || {};
    if (!text || typeof text !== "string") {
      return res.status(400).json({ code: "BAD_INPUT", error: "Text is required." });
    }

    const salt = crypto.randomBytes(16); // for KDF
    const iv = crypto.randomBytes(12);   // GCM IV = 12 bytes recommended
    const key = getKey({ passphrase, keyB64, salt });

    const cipher = crypto.createCipheriv(ALGO, key, iv);
    const ciphertext = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();

    const pkgObj = {
      v: 1,
      algorithm: ALGO,
      kdf: KDF,
      kdfHash: KDF_HASH,
      iterations: PBKDF2_ITER,
      keyLength: KEY_LEN * 8,
      salt: b64(salt),
      iv: b64(iv),
      tag: b64(tag),
      ciphertext: b64(ciphertext),
      // You can include metadata like timestamp if needed
      ts: Date.now(),
    };

    const pkg = b64(Buffer.from(JSON.stringify(pkgObj), "utf8"));
    const response = {
      package: pkg,
      report: {
        inputPreview: text.slice(0, 32),
        algorithm: ALGO,
        kdf: `${KDF}-${KDF_HASH}`,
        iterations: PBKDF2_ITER,
        keyLengthBits: KEY_LEN * 8,
        salt: pkgObj.salt,
        iv: pkgObj.iv,
        authTag: pkgObj.tag,
        ciphertext: pkgObj.ciphertext,
      },
    };

    // Return the random key only if it was auto-generated
    if (!passphrase && !keyB64) {
      response.generatedKeyB64 = b64(key);
      response.note = "No passphrase supplied; a random key was generated. Save it to decrypt.";
    }

    return res.json(response);
  } catch (err) {
    console.error("encryptText error:", err);
    if (err.message === "INVALID_KEY_LENGTH") {
      return res.status(400).json({ code: "INVALID_KEY", error: "Key must be 32 bytes (base64-encoded)." });
    }
    return res.status(500).json({ code: "ENCRYPT_FAIL", error: "Encryption failed." });
  }
};

export const decryptText = (req, res) => {
  try {
    const { package: pkg, passphrase, keyB64 } = req.body || {};
    if (!pkg) {
      return res.status(400).json({ code: "BAD_INPUT", error: "Encrypted package is required." });
    }

    let obj;
    try {
      obj = JSON.parse(Buffer.from(pkg, "base64").toString("utf8"));
    } catch {
      return res.status(400).json({ code: "BAD_PACKAGE", error: "Invalid encrypted package." });
    }

    const { algorithm, salt, iv, tag, ciphertext, iterations, kdfHash } = obj;
    if (algorithm !== ALGO) {
      return res.status(400).json({ code: "WRONG_ALGO", error: `Unsupported algorithm: ${algorithm}` });
    }
    if (iterations !== PBKDF2_ITER || kdfHash !== KDF_HASH) {
      // Not strictly required; you could just use the values in obj instead
      // but warning helps keep consistency.
      // We'll still decrypt using the values from obj.
    }

    const key = getKey({
      passphrase,
      keyB64,
      salt: ub64(salt),
    });

    const decipher = crypto.createDecipheriv(ALGO, key, ub64(iv));
    decipher.setAuthTag(ub64(tag));

    const plaintext = Buffer.concat([
      decipher.update(ub64(ciphertext)),
      decipher.final(),
    ]).toString("utf8");

    return res.json({
      decrypted: plaintext,
      integrity: "verified",
      report: {
        algorithm: obj.algorithm,
        kdf: `${obj.kdf}-${obj.kdfHash}`,
        iterations: obj.iterations,
        keyLengthBits: obj.keyLength,
        salt: obj.salt,
        iv: obj.iv,
        authTag: obj.tag,
        ciphertext: obj.ciphertext,
      },
    });
  } catch (err) {
    console.error("decryptText error:", err);
    return res.status(400).json({ code: "DECRYPT_FAIL", error: "Invalid package or wrong passphrase/key." });
  }
};
