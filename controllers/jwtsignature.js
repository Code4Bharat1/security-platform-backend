// controllers/jwtSignature.controller.js
import jwt from "jsonwebtoken";
import JWTSignature from "../models/jwtsignature.model.js";

const ALLOWED_ALGS = [
  "HS256","HS384","HS512",
  "RS256","RS384","RS512",
  "ES256","ES384","ES512",
];

export const validateJWT = async (req, res) => {
  const { token, secret, algorithm = "auto" } = req.body;

  if (!token || !secret) {
    return res.status(400).json({ error: "Token and secret/key are required" });
  }

  const cleanToken = String(token).trim();
  const cleanSecret = String(secret).trim();

  const parts = cleanToken.split(".");
  if (parts.length !== 3) {
    return res
      .status(400)
      .json({ error: `Invalid JWT format. Found ${parts.length} parts, expected 3.` });
  }

  // Decode header to know what alg the token claims
  let headerFromToken;
  try {
    headerFromToken = JSON.parse(
      Buffer.from(parts[0], "base64url").toString("utf8")
    );
  } catch {
    return res.status(400).json({ error: "Unable to decode JWT header" });
  }

  // Reject alg=none explicitly (insecure)
  if (String(headerFromToken.alg || "").toUpperCase() === "NONE" ||
      String(headerFromToken.alg || "").toUpperCase() === "NONE") {
    return res.status(400).json({ error: "Insecure token (alg=none) is not allowed" });
  }

  // Build verification options
  const opts = { complete: true };

  if (algorithm !== "auto") {
    if (!ALLOWED_ALGS.includes(algorithm)) {
      return res.status(400).json({ error: `Unsupported algorithm: ${algorithm}` });
    }
    opts.algorithms = [algorithm];
  } else {
    // lock to the token's declared alg to avoid alg confusion
    const declared = String(headerFromToken.alg || "").toUpperCase();
    if (!ALLOWED_ALGS.includes(declared)) {
      return res.status(400).json({ error: `Unsupported or missing alg in token header: ${declared || "N/A"}` });
    }
    opts.algorithms = [declared];
  }

  // If algorithm is asymmetric, secret must be a PEM public key/cert
  const isAsymmetric = /^(RS|ES)/.test(opts.algorithms[0]);
  if (isAsymmetric) {
    const looksLikePEM = /-----BEGIN (PUBLIC KEY|CERTIFICATE)-----/.test(cleanSecret);
    if (!looksLikePEM) {
      return res.status(400).json({
        error: `For ${opts.algorithms[0]}, provide a PEM-formatted public key or certificate.`,
      });
    }
  }

  try {
    const verified = jwt.verify(cleanToken, cleanSecret, opts); // throws if invalid
    const { header, payload } = verified;

    // Save success (non-blocking)
    try {
      await new JWTSignature({
        token: cleanToken,
        secret: cleanSecret,
        valid: true,
        header,
        payload,
        algorithm: opts.algorithms[0],
      }).save();
    } catch (_) {}

    return res.json({
      message: "JWT signature is valid",
      header,
      payload,
    });
  } catch (err) {
    // Save failure (non-blocking)
    try {
      await new JWTSignature({
        token: cleanToken,
        secret: cleanSecret,
        valid: false,
        algorithm: opts.algorithms?.[0],
        error: err.message,
      }).save();
    } catch (_) {}

    let errorMessage = "Invalid JWT signature or token";
    if (err.name === "TokenExpiredError") errorMessage = "JWT token has expired";
    else if (err.name === "JsonWebTokenError") {
      if (err.message.includes("invalid signature")) errorMessage = "Invalid JWT signature - check your secret/key";
      else if (err.message.includes("malformed")) errorMessage = "Malformed JWT token";
      else errorMessage = `JWT Error: ${err.message}`;
    } else if (err.name === "NotBeforeError") errorMessage = "JWT token is not active yet";

    return res.status(400).json({ error: errorMessage });
  }
};
