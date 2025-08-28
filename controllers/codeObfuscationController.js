// controllers/codeObfuscationController.js
import { CodeObfuscation } from "../models/codeObfuscationModel.js";

/* ---------- detectors (per-line + whole-file) ---------- */
const RX = {
  // per-line
  unicodeEsc: /\\u[0-9a-fA-F]{4}/g,
  base64InQuotes: /(['"`])([A-Za-z0-9+/]{16,}={0,2})\1/g, // long-ish base64 strings
  evalCall: /\beval\s*\(/g,
  funcCtor: /\bnew\s+Function\s*\(|\bFunction\s*\(/g,
  iife: /\(\s*function\s*\([^)]*\)\s*\{[\s\S]*?\}\s*\)\s*\(/g,
  dynamicProp: /\[\s*(?:(['"`])[^'"`]*\1\s*(?:\+\s*\1[^'"`]*\1\s*)+|(['"`])[^'"`]+\2)\s*\]/g,
  stringConcat: /(['"`][^'"`]*['"`]\s*(?:\+\s*['"`][^'"`]*['"`]\s*){1,})/g,
  deadCode: /\bif\s*\(\s*(?:false|0)\s*\)\s*\{|\bwhile\s*\(\s*(?:false|0)\s*\)/g,
  setTimeoutString: /\bset(?:Timeout|Interval)\s*\(\s*(['"`])/g,
  // whole file (simple heuristic)
  shortVarDecl: /\b(?:var|let|const)\s+([a-zA-Z_$]{1,2})\b/g,
};

function analyzeOne(name, codeText) {
  const lines = String(codeText || "").split(/\r?\n/);

  // counts & line highlights
  const counters = {
    evalCount: 0,
    functionCtorCount: 0,
    iifeCount: 0,
    unicodeEscapesCount: 0,
    base64StringsCount: 0,
    dynamicPropsCount: 0,
    stringSplitsCount: 0,
    deadCodeCount: 0,
    setTimeoutStringCount: 0,
    shortVarsCount: 0,
  };

  const shortVars = new Set();
  for (const m of String(codeText).matchAll(RX.shortVarDecl)) {
    shortVars.add(m[1]);
  }
  counters.shortVarsCount = shortVars.size;

  const highlights = []; // { line, level: 'low'|'medium'|'high'|'none', reasons: [] }
  const issues = [];

  lines.forEach((ln, idx) => {
    const lineNo = idx + 1;
    const reasons = [];
    let score = 0;

    const add = (reason, weight, counterKey) => {
      reasons.push(reason);
      score += weight;
      if (counterKey) counters[counterKey]++;
    };

    if (RX.evalCall.test(ln)) add("uses eval()", 30, "evalCount");
    if (RX.funcCtor.test(ln)) add("dynamic Function constructor", 30, "functionCtorCount");
    if (RX.iife.test(ln)) add("IIFE pattern", 5, "iifeCount");
    if (RX.unicodeEsc.test(ln)) add("Unicode escaped string", 10, "unicodeEscapesCount");
    if (RX.base64InQuotes.test(ln)) add("Base64-looking string", 20, "base64StringsCount");
    if (RX.dynamicProp.test(ln)) add("Dynamic property access", 10, "dynamicPropsCount");
    if (RX.stringConcat.test(ln)) add("String splitting/concatenation", 10, "stringSplitsCount");
    if (RX.deadCode.test(ln)) add("Dead code / impossible branch", 10, "deadCodeCount");
    if (RX.setTimeoutString.test(ln)) add("Timer with string code", 10, "setTimeoutStringCount");

    let level = "none";
    if (score >= 30) level = "high";
    else if (score >= 15) level = "medium";
    else if (score > 0) level = "low";

    highlights.push({ line: lineNo, level, reasons });
  });

  // de-obfuscation preview
  const deobfuscationPreview = {
    base64Decoded: [],
    unicodeDecoded: [],
    collapsedStrings: [],
  };

  lines.forEach((ln, idx) => {
    let m;

    // Base64 strings
    while ((m = RX.base64InQuotes.exec(ln))) {
      const b64 = m[2];
      try {
        const decoded = Buffer.from(b64, "base64").toString("utf8");
        // only add if looks printable
        if (/[\x09\x0A\x0D\x20-\x7E]{4,}/.test(decoded))
          deobfuscationPreview.base64Decoded.push({
            line: idx + 1,
            original: b64.slice(0, 60),
            decoded: decoded.slice(0, 120),
          });
      } catch {}
    }

    // Unicode \uXXXX
    if (RX.unicodeEsc.test(ln)) {
      const converted = ln.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) =>
        String.fromCharCode(parseInt(h, 16))
      );
      deobfuscationPreview.unicodeDecoded.push({
        line: idx + 1,
        original: ln.slice(0, 80),
        decoded: converted.slice(0, 120),
      });
    }

    // "h"+"e"+"l"+"l"+"o"
    while ((m = RX.stringConcat.exec(ln))) {
      const grp = m[1];
      const collapsed = grp
        .replace(/\s*\+\s*/g, "")
        .replace(/^(['"`])|(['"`])$/g, "")
        .replace(/(['"`])/g, ""); // crude collapse
      deobfuscationPreview.collapsedStrings.push({
        line: idx + 1,
        original: grp.slice(0, 80),
        collapsed: collapsed.slice(0, 120),
      });
    }
  });

  // 0–100 score with weights
  let score = 0;
  const addScore = (pts, n = 1, cap = pts) => (score += Math.min(pts * n, cap));

  addScore(10, counters.shortVarsCount ? 1 : 0, 10);
  addScore(20, counters.base64StringsCount, 40);
  addScore(30, counters.evalCount + counters.functionCtorCount, 60);
  addScore(10, counters.unicodeEscapesCount, 20);
  addScore(10, counters.dynamicPropsCount, 20);
  addScore(10, counters.stringSplitsCount, 20);
  addScore(10, counters.deadCodeCount + counters.setTimeoutStringCount, 30);
  addScore(5, counters.iifeCount, 10);

  score = Math.max(0, Math.min(100, score));

  const severity = score >= 70 ? "High" : score >= 30 ? "Medium" : "Low";

  if (counters.evalCount) issues.push("Avoid eval() — dangerous & often used in obfuscation.");
  if (counters.functionCtorCount) issues.push("Dynamic Function() detected.");
  if (counters.base64StringsCount)
    issues.push("Base64-looking strings present — inspect decoded content.");
  if (counters.unicodeEscapesCount) issues.push("Unicode escapes may hide readable code.");
  if (counters.dynamicPropsCount) issues.push("Dynamic property access can hide intent.");
  if (counters.deadCodeCount) issues.push("Dead code injection patterns present.");
  if (counters.stringSplitsCount) issues.push("String splitting/concatenation used.");
  if (counters.shortVarsCount >= 5) issues.push("Many short variable names (low readability).");

  const metrics = {
    shortVars: Array.from(shortVars),
    shortVarsCount: counters.shortVarsCount,
    encodedStringsCount: counters.base64StringsCount,
    evalCount: counters.evalCount,
    functionCtorCount: counters.functionCtorCount,
    iifeCount: counters.iifeCount,
    unicodeEscapesCount: counters.unicodeEscapesCount,
    dynamicPropsCount: counters.dynamicPropsCount,
    stringSplitsCount: counters.stringSplitsCount,
    deadCodeCount: counters.deadCodeCount,
    setTimeoutStringCount: counters.setTimeoutStringCount,
  };

  return {
    name,
    code: codeText,
    score,
    severity,
    metrics,
    highlights,
    issues,
    deobfuscationPreview,
  };
}

/* ---------- public controller ---------- */
export const analyzeCodeObfuscation = async (req, res) => {
  try {
    const { code, files } = req.body || {};

    const work = [];
    if (Array.isArray(files) && files.length) {
      files.forEach((f) =>
        work.push({ name: f.name || "file", content: String(f.content || "") })
      );
    } else if (typeof code === "string") {
      work.push({ name: "pasted-code.js", content: code });
    } else {
      return res.status(400).json({ error: "Provide { code } or { files:[{name,content}...] }" });
    }

    const results = work.map(({ name, content }) => analyzeOne(name, content));

    // optional DB save (trim large code)
    try {
      await CodeObfuscation.create({
        code: work[0]?.content?.slice(0, 10000) || "",
        severity: results[0]?.severity,
        shortVars: results[0]?.metrics?.shortVars || [],
        encodedStringsCount: results[0]?.metrics?.encodedStringsCount || 0,
        usesEval: (results[0]?.metrics?.evalCount || 0) > 0,
        extra: { score: results[0]?.score },
      });
    } catch (e) {
      // non-fatal
    }

    res.json({ results });
  } catch (err) {
    console.error("Obfuscation analysis error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
};
