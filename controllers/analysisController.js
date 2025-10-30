// controllers/analysisController.js
import { Analysis } from "../models/analysisModel.js";

// ---- Heuristic rules & helpers ----
const SEVERITY = { Low: 'Low', Medium: 'Medium', High: 'High', Critical: 'Critical' };
const severityWeights = { Low: 10, Medium: 20, High: 30, Critical: 40 };
const FIX = {
  XSS_INNER_HTML:
    "Avoid innerHTML/outerHTML/insertAdjacentHTML. Prefer textContent, or sanitize with a vetted library (e.g., DOMPurify).",
  XSS_REACT_DANGEROUS:
    "Avoid dangerouslySetInnerHTML. If unavoidable, sanitize input and whitelist allowed tags/attributes.",
  XSS_DOCUMENT_WRITE:
    "Avoid document.write(). Use safer DOM APIs and sanitized text nodes.",
  EVAL:
    "Avoid eval/new Function and string-based setTimeout/setInterval. Use callbacks, JSON.parse, or safer parsers.",
  SQLI:
    "Use parameterized queries / prepared statements. Never concatenate user input into SQL strings.",
};

const scoreBand = (score) =>
  score >= 90 ? "Critical" :
    score >= 70 ? "High" :
      score >= 40 ? "Medium" :
        score > 0 ? "Low" : "Safe";

const sumToScore = (issues) =>
  Math.min(100, issues.reduce((acc, it) => acc + (severityWeights[it.severity] || 0), 0));

function addIssue(issues, { line, snippet, type, severity, message, fix }) {
  issues.push({
    line,
    snippet: String(snippet || "").trim().slice(0, 400),
    type,
    severity,
    message,
    fix,
  });
}

function scanJavaScriptLike(code, language) {
  const issues = [];
  const lines = code.split(/\r?\n/);

  lines.forEach((line, idx) => {
    const t = line.trim();

    // XSS sinks
    if (/\b(innerHTML|outerHTML|insertAdjacentHTML)\b/.test(t)) {
      addIssue(issues, {
        line: idx + 1,
        snippet: line,
        type: "XSS",
        severity: SEVERITY.High,
        message: "Potential DOM XSS sink (innerHTML/outerHTML/insertAdjacentHTML).",
        fix: FIX.XSS_INNER_HTML,
      });
    }
    if (/document\.(write|writeln)\s*\(/.test(t)) {
      addIssue(issues, {
        line: idx + 1,
        snippet: line,
        type: "XSS",
        severity: SEVERITY.High,
        message: "document.write() can lead to XSS and blocking issues.",
        fix: FIX.XSS_DOCUMENT_WRITE,
      });
    }
    if (/\$\([^)]*\)\.html\s*\(/.test(t)) {
      addIssue(issues, {
        line: idx + 1,
        snippet: line,
        type: "XSS",
        severity: SEVERITY.High,
        message: "jQuery .html() is an XSS sink if fed untrusted input.",
        fix: FIX.XSS_INNER_HTML,
      });
    }
    if (language === "react" && /dangerouslySetInnerHTML\s*:/.test(t)) {
      addIssue(issues, {
        line: idx + 1,
        snippet: line,
        type: "XSS",
        severity: SEVERITY.High,
        message: "React dangerouslySetInnerHTML used.",
        fix: FIX.XSS_REACT_DANGEROUS,
      });
    }
    if (language === "vue" && /\bv-html\s*=/.test(t)) {
      addIssue(issues, {
        line: idx + 1,
        snippet: line,
        type: "XSS",
        severity: SEVERITY.High,
        message: "Vue v-html renders raw HTML; can XSS if unsanitized.",
        fix: FIX.XSS_INNER_HTML,
      });
    }

    // Dangerous eval
    if (/\beval\s*\(/.test(t) || /new\s+Function\s*\(/.test(t)) {
      addIssue(issues, {
        line: idx + 1,
        snippet: line,
        type: "Eval",
        severity: SEVERITY.Critical,
        message: "Use of eval/new Function detected.",
        fix: FIX.EVAL,
      });
    }
    // FIX: correctly detect string-based setTimeout / setInterval
    if (/set(?:Timeout|Interval)\s*\(\s*['"]/.test(t)) {
      addIssue(issues, {
        line: idx + 1,
        snippet: line,
        type: "Eval",
        severity: SEVERITY.Medium,
        message: "String-based setTimeout/setInterval executes code via eval semantics.",
        fix: FIX.EVAL,
      });
    }
  });

  return issues;
}

function scanSQLiHeuristics(code) {
  const issues = [];
  const lines = code.split(/\r?\n/);
  const selectRegex = /\bSELECT\b/i;

  lines.forEach((line, idx) => {
    if (!selectRegex.test(line)) return;

    // heuristics for concatenation of variables into SQL
    const likelyConcat =
      /(["'`]\s*\+\s*\w)|(\$\w+\s*\.)|(\+\s*\w+\s*\+)/.test(line) ||
      /\bWHERE\b[^;]*([=<>]\s*["'`]\s*\+|\$\w+)/i.test(line);

    const severity = likelyConcat ? SEVERITY.Critical : SEVERITY.High;
    const message = likelyConcat
      ? "Possible SQL injection: query appears to concatenate variables into SQL."
      : "Raw SELECT detected. Ensure the query is parameterized.";

    addIssue(issues, {
      line: idx + 1,
      snippet: line,
      type: "SQLi",
      severity,
      message,
      fix: FIX.SQLI,
    });
  });

  return issues;
}

function analyzeStatic(code, language = "javascript") {
  let issues = [];
  const lang = String(language || "javascript").toLowerCase();

  if (["javascript", "typescript", "react", "vue"].includes(lang)) {
    issues = issues.concat(scanJavaScriptLike(code, lang));
  }
  // Always scan for SQL-like patterns
  issues = issues.concat(scanSQLiHeuristics(code));

  // dedupe (line + message)
  const seen = new Set();
  issues = issues.filter((it) => {
    const k = `${it.line}|${it.message}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });

  const riskScore = sumToScore(issues);
  const riskBand = scoreBand(riskScore);
  return { issues, riskScore, riskBand };
}

// ---- Controller ----
export const analyzeCode = async (req, res) => {
  try {
    const { code, language = "javascript" } = req.body || {};
    if (!code || typeof code !== "string") {
      return res.status(400).json({ error: "Invalid code input." });
    }

    const { issues, riskScore, riskBand } = analyzeStatic(code, language);

    // Save non-fatal
    let analysisId = null;
    try {
      const saved = await Analysis.create?.({ code, issues, riskScore, riskBand });
      analysisId = saved?._id?.toString?.() || null;
    } catch (saveErr) {
      console.warn("Analysis save skipped (schema may be strict):", saveErr?.message);
    }

    return res.status(200).json({ analysisId, language, riskScore, riskBand, issues });
  } catch (err) {
    console.error("Error analyzing code:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
};
