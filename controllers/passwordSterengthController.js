import PasswordMetric from "../models/passwordStrength.js";

// constants & helpers
const SYMBOLS = ` !"#$%&'()*+,-./:;<=>?@[\\]^_\`{|}~`;
const GUESSES_PER_SECOND = 1e10;

const hasLower = s => /[a-z]/.test(s);
const hasUpper = s => /[A-Z]/.test(s);
const hasDigit = s => /[0-9]/.test(s);
const hasSymbol = s => /[^A-Za-z0-9]/.test(s);

function charsetSize(pw){
  let n = 0;
  if (hasLower(pw)) n += 26;
  if (hasUpper(pw)) n += 26;
  if (hasDigit(pw)) n += 10;
  if (hasSymbol(pw)) n += SYMBOLS.length;
  return Math.max(n, 1);
}
function bitsOfEntropy(pw){ return pw.length * Math.log2(charsetSize(pw)); }
function crackTimeSeconds(bits){
  const expected = Math.pow(2, Math.max(bits - 1, 0));
  return expected / GUESSES_PER_SECOND;
}
function humanizeSeconds(sec){
  if (!isFinite(sec) || sec < 1) return "< 1 sec";
  const units = [["year",31536000],["day",86400],["hour",3600],["min",60],["sec",1]];
  for (const [name,s] of units) if (sec >= s) {
    const v = Math.floor(sec/s); return `${v} ${name}${v>1?"s":""}`;
  }
  return "seconds";
}
function score(bits){ return Math.max(0, Math.min(100, Math.round((bits/80)*100))); }
function label(bits){
  if (bits < 35) return "Weak";
  if (bits < 60) return "Medium";
  if (bits < 80) return "Strong";
  return "Very Strong";
}
function advice(pw){
  const tips = [];
  if (pw.length < 12) tips.push("Use at least 12–16 characters.");
  if (!hasLower(pw)) tips.push("Add lowercase letters.");
  if (!hasUpper(pw)) tips.push("Add uppercase letters.");
  if (!hasDigit(pw)) tips.push("Add numbers.");
  if (!hasSymbol(pw)) tips.push("Add symbols.");
  if (/([a-zA-Z0-9])\1\1/.test(pw)) tips.push("Avoid repeating the same character 3+ times.");
  if (/(1234|abcd|qwer|password|admin|letmein)/i.test(pw)) tips.push("Avoid common words or sequences.");
  return tips;
}

export async function analyzePassword(req, res){
  try {
    const { password } = req.body || {};
    if (typeof password !== "string") {
      return res.status(400).json({ message: "Password is required." });
    }
    if (password.length > 256) {
      return res.status(400).json({ message: "Password is too long (max 256)." });
    }

    const length = password.length;
    const classes = {
      lower: hasLower(password),
      upper: hasUpper(password),
      number: hasDigit(password),
      symbol: hasSymbol(password),
    };

    const bits = bitsOfEntropy(password);
    const seconds = crackTimeSeconds(bits);
    const payload = {
      length,
      classes,
      entropyBits: Math.round(bits * 10) / 10,
      crackTime: {
        seconds,
        human: humanizeSeconds(seconds),
        assumptions: { guessesPerSecond: GUESSES_PER_SECOND }
      },
      score: score(bits),
      label: label(bits),
      advice: advice(password),
    };

    // OPTIONAL: persist metrics (no raw password)
    if (process.env.LOG_PASSWORD_METRICS === "1") {
      try {
        await PasswordMetric.create({
          length,
          classes,
          entropyBits: payload.entropyBits,
          crackTimeSeconds: seconds,
          score: payload.score,
          label: payload.label,
          advice: payload.advice,
          ip: req.ip,
          ua: req.get("user-agent"),
        });
      } catch (e) {
        // don't fail the request if logging fails
        console.warn("PasswordMetric save skipped:", e?.message || e);
      }
    }

    return res.json(payload);
  } catch (e) {
    console.error("analyzePassword error:", e);
    res.status(500).json({ message: "Unexpected server error." });
  }
}
