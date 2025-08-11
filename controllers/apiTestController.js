// backend/controllers/apiTestController.js
import axios from "axios";
import apiTestModel from "../models/apiTestModel.js";

const MAX_RESPONSE_BYTES = 200_000; // ~200KB cap to avoid huge Mongo docs

const testAPIWithSecurity = async (url, method, headers, body, options = {}) => {
  try {
    const startTime = Date.now();

    const response = await axios.request({
      url,
      method,
      headers: {
        "User-Agent": "API-Security-Tester/1.0",
        Accept: "*/*",
        ...headers,
      },
      data: method !== "GET" && method !== "HEAD" ? body : undefined,
      timeout: options.timeout || 5000,
      validateStatus: () => true,     // never throw on HTTP codes
      maxRedirects: 5,
      responseType: "text",           // capture anything as text
      transformResponse: [(data) => data], // prevent axios from auto-parsing
    });

    const endTime = Date.now();

    // Try to parse JSON (without throwing)
    let parsedData = null;
    try {
      parsedData = JSON.parse(response.data);
    } catch {
      parsedData = response.data;
    }

    // Cap the stored response to keep DB sane
    let dataForStore = parsedData;
    if (typeof dataForStore === "string" && dataForStore.length > MAX_RESPONSE_BYTES) {
      dataForStore = dataForStore.slice(0, MAX_RESPONSE_BYTES) + "\n/* truncated */";
    }

    const securityAnalysis = performSecurityAnalysis(response, url);

    const result = {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers || {},
      data: dataForStore,
      responseTime: endTime - startTime,
      securityChecks: securityAnalysis.checks,
      securityScorecard: securityAnalysis.scorecard,
      recommendations: securityAnalysis.recommendations,
      timestamp: new Date().toISOString(),
    };

    // Surface allowed methods on 405 for better UX
    if (response.status === 405 && response.headers?.allow) {
      result.note = `Method Not Allowed. Allowed methods: ${response.headers.allow}`;
    }

    return result;
  } catch (error) {
    console.error(`Error calling API: ${error.code || ""} ${error.message}`);

    let friendly = error.message;
    if (error.code === "ECONNABORTED") friendly = "Request timeout - API took too long to respond";
    else if (error.code === "ENOTFOUND") friendly = "Host not found - Check if the URL is correct";
    else if (error.code === "ECONNREFUSED") friendly = "Connection refused - The server is not accepting connections";

    return { error: friendly };
  }
};

const performSecurityAnalysis = (response, url) => {
  let score = 100;
  const checks = {};
  const recommendations = [];

  const headers = response.headers || {}; // guard
  const h = (k) => headers[k.toLowerCase()]; // case-insensitive helper

  const isHttps = url.startsWith("https://");
  checks.ssl = {
    status: isHttps ? "Secure" : "Insecure",
    hstsStatus: h("strict-transport-security") ? "Enabled" : "Missing",
  };
  if (!isHttps) {
    score -= 30;
    recommendations.push("Use HTTPS instead of HTTP for secure communication");
    checks.ssl.recommendation = "Switch to HTTPS to encrypt data in transit";
  }
  if (!h("strict-transport-security")) {
    score -= 10;
    recommendations.push("Implement HSTS (Strict-Transport-Security) header");
  }

  const securityHeaders = {
    "X-Content-Type-Options": {
      present: !!h("x-content-type-options"),
      recommendation: "Add X-Content-Type-Options: nosniff header to prevent MIME sniffing",
    },
    "X-Frame-Options": {
      present: !!h("x-frame-options"),
      recommendation: "Add X-Frame-Options header to prevent clickjacking attacks",
    },
    "X-XSS-Protection": {
      present: !!h("x-xss-protection"),
      recommendation: "Add X-XSS-Protection header to enable XSS filtering",
    },
    "Content-Security-Policy": {
      present: !!h("content-security-policy"),
      recommendation: "Implement Content Security Policy (CSP) header to prevent XSS attacks",
    },
    "Referrer-Policy": {
      present: !!h("referrer-policy"),
      recommendation: "Add Referrer-Policy header to control referrer information leakage",
    },
  };

  checks.headerSecurity = {};
  Object.entries(securityHeaders).forEach(([header, info]) => {
    const present = info.present;
    checks.headerSecurity[header] = {
      status: present ? "Configured" : "Missing",
      recommendation: present ? null : info.recommendation,
    };
    if (!present) {
      score -= 8;
      recommendations.push(info.recommendation);
    }
  });

  const hasAuth =
    h("www-authenticate") ||
    response.config?.headers?.authorization ||
    response.config?.headers?.["x-api-key"];
  checks.authentication = {
    status: hasAuth ? "Present" : "Not Detected",
    secure: response.config?.headers?.authorization?.startsWith?.("Bearer ")
      ? "Using Bearer token authentication"
      : "Review authentication method security",
  };

  const parsedForAnalysis =
    typeof response.data === "string"
      ? (() => { try { return JSON.parse(response.data); } catch { return response.data; } })()
      : response.data;

  checks.sensitiveDataExposure = analyzeSensitiveData(parsedForAnalysis);
  if (checks.sensitiveDataExposure.status !== "No obvious data exposure") {
    score -= 20;
    recommendations.push("Review response data for sensitive information exposure");
  }

  checks.injectionVulnerability = analyzeInjectionVulnerabilities(parsedForAnalysis);
  if (checks.injectionVulnerability.status !== "No obvious vulnerabilities") {
    score -= 25;
    recommendations.push("Review error handling to prevent information disclosure");
  }

  if (response.status >= 500) {
    score -= 15;
    recommendations.push("Server errors may expose sensitive information - implement proper error handling");
  }

  ["server", "x-powered-by", "x-aspnet-version"].forEach((name) => {
    if (h(name)) {
      score -= 5;
      recommendations.push(`Consider removing '${name}' header to reduce information disclosure`);
    }
  });

  score = Math.max(0, Math.min(100, score));
  const rating = score >= 80 ? "Excellent" : score >= 60 ? "Good" : score >= 40 ? "Fair" : "Poor";

  return {
    checks,
    scorecard: { score: Math.round(score), rating },
    recommendations: [...new Set(recommendations)],
  };
};

const analyzeSensitiveData = (data) => {
  const str = (typeof data === "string" ? data : JSON.stringify(data || {})).toLowerCase();
  const patterns = [
    { pattern: /password/gi, type: "password" },
    { pattern: /secret/gi, type: "secret" },
    { pattern: /token/gi, type: "token" },
    { pattern: /api[_-]?key/gi, type: "api_key" },
    { pattern: /credit[_-]?card/gi, type: "credit_card" },
    { pattern: /ssn|social[_-]?security/gi, type: "ssn" },
    { pattern: /\b\d{4}[_-]?\d{4}[_-]?\d{4}[_-]?\d{4}\b/g, type: "card_number" },
    { pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, type: "email" },
  ];

  const found = [];
  patterns.forEach(({ pattern, type }) => {
    const matches = str.match(pattern);
    if (matches) found.push({ type, count: matches.length });
  });

  return found.length
    ? { status: "Potential sensitive data detected", details: found }
    : { status: "No obvious data exposure", details: "No sensitive data patterns detected in response" };
};

const analyzeInjectionVulnerabilities = (data) => {
  const str = typeof data === "string" ? data : JSON.stringify(data || {});
  const patterns = [
    { pattern: /sql.*error/gi, type: "SQL Error" },
    { pattern: /mysql.*error/gi, type: "MySQL Error" },
    { pattern: /oracle.*error/gi, type: "Oracle Error" },
    { pattern: /postgresql.*error/gi, type: "PostgreSQL Error" },
    { pattern: /syntax.*error.*near/gi, type: "SQL Syntax Error" },
    { pattern: /warning.*mysql_/gi, type: "MySQL Warning" },
    { pattern: /fatal.*error/gi, type: "Fatal Error" },
    { pattern: /stack trace/gi, type: "Stack Trace" },
  ];

  const found = [];
  patterns.forEach(({ pattern, type }) => {
    if (pattern.test(str)) found.push(type);
  });

  return found.length
    ? { status: "Potential vulnerability indicators detected", details: found }
    : { status: "No obvious vulnerabilities", details: "No common error patterns detected in response" };
};

export const testApi = async (req, res) => {
  const { url, method, headers, body, options } = req.body || {};

  if (!url || !method) {
    return res.status(400).json({ error: "URL and method are required" });
  }

  const result = await testAPIWithSecurity(url, method, headers, body, options);

  if (result.error) {
    return res.status(502).json({ error: result.error }); // 502: upstream fetch failed
  }

  try {
    await new apiTestModel({
      url,
      method,
      headers,
      body,
      status: result.status,
      statusText: result.statusText,
      responseTime: result.responseTime,
      responseHeaders: result.headers,
      responseData: result.data,
      securityChecks: result.securityChecks,
      securityScorecard: result.securityScorecard,
      recommendations: result.recommendations,
    }).save();
  } catch (err) {
    console.error("Error saving test result:", err.message);
    // Don't fail the user response if persistence fails
  }

  return res.status(200).json(result);
};
