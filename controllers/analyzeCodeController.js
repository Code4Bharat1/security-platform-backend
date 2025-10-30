// controllers/analysisController.js
import { Analysis } from "../models/analysisModel.js"; // optional, can be undefined

// ---- Severity & Fixes ----
const SEVERITY = { Low: "Low", Medium: "Medium", High: "High", Critical: "Critical" };
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
  REDIRECT:
    "Validate and sanitize redirect targets; avoid direct assignment from user input.",
};

// ---- Helpers ----
const scoreBand = (score) =>
  score >= 90 ? "Critical" : score >= 70 ? "High" : score >= 40 ? "Medium" : score > 0 ? "Low" : "Safe";

const sumToScore = (issues) =>
  Math.min(100, issues.reduce((acc, it) => acc + (severityWeights[it.severity] || 0), 0));

function addIssue(issues, { line, snippet, type, severity, message, fix }) {
  issues.push({
    line: line || 0,
    snippet: String(snippet || "").trim().slice(0, 400),
    type: type || "Unknown",
    severity: severity || SEVERITY.Low,
    message: message || "",
    fix: fix || null,
  });
}

// ---- JavaScript / React / Vue Scanner ----
function scanJavaScriptLike(code) {
  const issues = [];
  const lines = code.split(/\r?\n/);

  lines.forEach((line, idx) => {
    const t = line.trim();
    const original = line;

    // XSS sinks - innerHTML, outerHTML, insertAdjacentHTML
    if (/\b(innerHTML|outerHTML|insertAdjacentHTML)\b/.test(t)) {
      addIssue(issues, {
        line: idx + 1,
        snippet: original,
        type: "XSS",
        severity: SEVERITY.High,
        message: "Potential DOM XSS sink (innerHTML/outerHTML/insertAdjacentHTML).",
        fix: FIX.XSS_INNER_HTML,
      });
    }

    // document.write() - XSS
    if (/document\s*\.\s*(write|writeln)\s*\(/.test(t)) {
      addIssue(issues, {
        line: idx + 1,
        snippet: original,
        type: "XSS",
        severity: SEVERITY.High,
        message: "document.write() can lead to XSS and blocking issues.",
        fix: FIX.XSS_DOCUMENT_WRITE,
      });
    }

    // jQuery .html() - XSS
    if (/\$\s*\([^)]*\)\s*\.\s*html\s*\(/.test(t)) {
      addIssue(issues, {
        line: idx + 1,
        snippet: original,
        type: "XSS",
        severity: SEVERITY.High,
        message: "jQuery .html() is an XSS sink if fed untrusted input.",
        fix: FIX.XSS_INNER_HTML,
      });
    }

    // React dangerouslySetInnerHTML - Fixed regex to handle JSX properly
    if (/dangerouslySetInnerHTML\s*=\s*\{\{/.test(t) || /dangerouslySetInnerHTML\s*=/.test(t)) {
      addIssue(issues, {
        line: idx + 1,
        snippet: original,
        type: "XSS",
        severity: SEVERITY.High,
        message: "React dangerouslySetInnerHTML used.",
        fix: FIX.XSS_REACT_DANGEROUS,
      });
    }

    // Vue v-html - Fixed regex to handle various formats
    if (/v-html\s*=\s*["']|v-html\s*=/.test(t)) {
      addIssue(issues, {
        line: idx + 1,
        snippet: original,
        type: "XSS",
        severity: SEVERITY.High,
        message: "Vue v-html renders raw HTML; can XSS if unsanitized.",
        fix: FIX.XSS_INNER_HTML,
      });
    }

    // eval() and new Function()
    if (/\beval\s*\(/.test(t) || /new\s+Function\s*\(/.test(t)) {
      addIssue(issues, {
        line: idx + 1,
        snippet: original,
        type: "Eval",
        severity: SEVERITY.Critical,
        message: "Use of eval/new Function detected.",
        fix: FIX.EVAL,
      });
    }

    // String-based setTimeout/setInterval
    if (/set(?:Timeout|Interval)\s*\(\s*['"`]/.test(t)) {
      addIssue(issues, {
        line: idx + 1,
        snippet: original,
        type: "Eval",
        severity: SEVERITY.Medium,
        message: "String-based setTimeout/setInterval executes code via eval semantics.",
        fix: FIX.EVAL,
      });
    }

    // window.location.href assignment
    if (/window\s*\.\s*location\s*\.\s*href\s*=/.test(t)) {
      addIssue(issues, {
        line: idx + 1,
        snippet: original,
        type: "PotentialRedirect",
        severity: SEVERITY.Medium,
        message: "Assignment to window.location.href detected — ensure the value is validated.",
        fix: FIX.REDIRECT,
      });
    }
  });

  return issues;
}

// ---- SQL Injection Heuristics ----
function scanSQLiHeuristics(code) {
  const issues = [];
  const lines = code.split(/\r?\n/);
  const selectRegex = /\bSELECT\b/i;

  lines.forEach((line, idx) => {
    if (!selectRegex.test(line)) return;

    const original = line;

    // Check if it's a parameterized query (safe patterns)
    const hasParameterizedQuery = /\?\s*[,);]|\$\d+|:\w+/.test(line);
    const hasPrepareStatement = /prepare\s*\(/i.test(line);

    // If it looks like a parameterized query, skip it
    if (hasParameterizedQuery && hasPrepareStatement) {
      return;
    }

    // Check for likely SQL injection (concatenation patterns)
    const likelyConcat =
      /(["'`]\s*\+\s*\w)|(\$\w+\s*\.)|(\+\s*\w+\s*\+)|(\+\s*["'`])/.test(line) ||
      /\bWHERE\b[^;]*([=<>]\s*["'`]\s*\+|\$\w+)/i.test(line) ||
      /["']\s*\+\s*\w+\s*\+\s*["']/.test(line);

    if (likelyConcat) {
      addIssue(issues, {
        line: idx + 1,
        snippet: original,
        type: "SQLi",
        severity: SEVERITY.Critical,
        message: "Possible SQL injection: query appears to concatenate variables into SQL.",
        fix: FIX.SQLI,
      });
    }
  });

  return issues;
}

// ---- Auto-language Detection ----
function detectLanguage(code) {
  const lower = code.toLowerCase();

  if (/dangerouslysetinnerhtml/.test(lower)) return "react";
  if (/v-html/.test(lower) || /<template>/i.test(code)) return "vue";
  if (/def\s+\w+\s*\(/.test(lower) || (/import\s+\w+/.test(lower) && lower.includes("python"))) return "python";
  if (/<\?php/i.test(code)) return "php";
  if (/\bSELECT\b/i.test(code) && /\$[a-zA-Z_]/.test(code)) return "php";
  return "javascript";
}

// ---- Static Analysis ----
function analyzeStatic(code) {
  const language = detectLanguage(code);
  let issues = [];

  // JS / React / Vue generic scanning
  issues = issues.concat(scanJavaScriptLike(code));

  // SQLi scanning
  issues = issues.concat(scanSQLiHeuristics(code));

  // Deduplicate by line + message
  const seen = new Set();
  issues = issues.filter((it) => {
    const k = `${it.line}|${it.message}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });

  const riskScore = sumToScore(issues);
  const riskBand = scoreBand(riskScore);

  return { issues, riskScore, riskBand, language };
}

// ---- Convert Issues for Frontend ----
function issuesToMessages(issues) {
  return issues.map((it) => {
    const linePart = it.line ? ` (Line ${it.line})` : "";
    const sev = it.severity ? `${it.severity}: ` : "";
    const typePart = it.type ? `[${it.type}] ` : "";
    return `${sev}${typePart}${it.message}${linePart}`;
  });
}

// ---- Controller ----
export const analyzeCode = async (req, res) => {
  try {
    const { code } = req.body || {};

    // Validation
    if (!code || typeof code !== "string") {
      return res.status(400).json({ error: "Invalid code input." });
    }

    if (code.trim().length === 0) {
      return res.status(400).json({ error: "Code cannot be empty." });
    }

    if (code.length > 100000) {
      return res.status(400).json({ error: "Code is too large. Maximum 100,000 characters allowed." });
    }

    // Static analysis with auto-language detection
    const { issues, riskScore, riskBand, language } = analyzeStatic(code);

    const messages = issuesToMessages(issues);
    const failed = issues.length;
    const passed = failed === 0 ? 1 : 0;

    // Save analysis if model exists
    let analysisId = null;
    try {
      if (typeof Analysis !== "undefined" && Analysis?.create) {
        const saved = await Analysis.create?.({
          code,
          issues,
          riskScore,
          riskBand,
          language,
          timestamp: new Date()
        });
        analysisId = saved?._id?.toString?.() || null;
      }
    } catch (saveErr) {
      console.warn("Analysis save skipped:", saveErr?.message || saveErr);
    }

    return res.status(200).json({
      analysisId,
      language,
      riskScore,
      riskBand,
      results: messages,
      passed,
      failed,
      issues,
    });
  } catch (err) {
    console.error("Error analyzing code:", err);
    return res.status(500).json({
      error: "Internal server error",
      details: process.env.NODE_ENV === "development" ? err.message : undefined
    });
  }
};

export default analyzeCode;
