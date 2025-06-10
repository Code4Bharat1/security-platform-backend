// backend/controllers/apiTestController.js
import axios from "axios";
import fetch from "node-fetch"; 

import apiTestModel from "../models/apiTestModel.js";

const testAPIWithSecurity = async (url, method, headers, body, options = {}) => {
  try {
    const startTime = Date.now();

    const response = await axios({
      url,
      method,
      headers: {
        "User-Agent": "API-Security-Tester/1.0",
        ...headers,
      },
      data: method !== "GET" && method !== "HEAD" ? body : undefined,
      timeout: options.timeout || 5000,
      validateStatus: () => true,
      maxRedirects: 5,
    });

    const endTime = Date.now();

    const securityAnalysis = performSecurityAnalysis(response, url);

    return {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
      data: response.data,
      responseTime: endTime - startTime,
      securityChecks: securityAnalysis.checks,
      securityScorecard: securityAnalysis.scorecard,
      recommendations: securityAnalysis.recommendations,
      timestamp: new Date().toISOString(),
    };
  } catch (error) {
    console.error(`Error calling API: ${error.message}`);
    return {
      error:
        error.code === "ECONNABORTED"
          ? "Request timeout - API took too long to respond"
          : error.code === "ENOTFOUND"
          ? "Host not found - Check if the URL is correct"
          : error.code === "ECONNREFUSED"
          ? "Connection refused - The server is not accepting connections"
          : error.message,
    };
  }
};

const performSecurityAnalysis = (response, url) => {
  let score = 100;
  const checks = {};
  const recommendations = [];

  const isHttps = url.startsWith("https://");
  checks.ssl = {
    status: isHttps ? "Secure" : "Insecure",
    hstsStatus: response.headers["strict-transport-security"] ? "Enabled" : "Missing",
  };
  if (!isHttps) {
    score -= 30;
    recommendations.push("Use HTTPS instead of HTTP for secure communication");
    checks.ssl.recommendation = "Switch to HTTPS to encrypt data in transit";
  }
  if (!response.headers["strict-transport-security"]) {
    score -= 10;
    recommendations.push("Implement HSTS (Strict-Transport-Security) header");
  }

  const securityHeaders = {
    "X-Content-Type-Options": {
      present: !!response.headers["x-content-type-options"],
      recommendation: "Add X-Content-Type-Options: nosniff header to prevent MIME sniffing",
    },
    "X-Frame-Options": {
      present: !!response.headers["x-frame-options"],
      recommendation: "Add X-Frame-Options header to prevent clickjacking attacks",
    },
    "X-XSS-Protection": {
      present: !!response.headers["x-xss-protection"],
      recommendation: "Add X-XSS-Protection header to enable XSS filtering",
    },
    "Content-Security-Policy": {
      present: !!response.headers["content-security-policy"],
      recommendation: "Implement Content Security Policy (CSP) header to prevent XSS attacks",
    },
    "Referrer-Policy": {
      present: !!response.headers["referrer-policy"],
      recommendation: "Add Referrer-Policy header to control referrer information leakage",
    },
  };

  checks.headerSecurity = {};
  Object.entries(securityHeaders).forEach(([header, info]) => {
    checks.headerSecurity[header] = {
      status: info.present ? "Configured" : "Missing",
      recommendation: info.present ? null : info.recommendation,
    };
    if (!info.present) {
      score -= 8;
      recommendations.push(info.recommendation);
    }
  });

  const hasAuth =
    response.headers["www-authenticate"] ||
    response.config?.headers?.authorization ||
    response.config?.headers?.["x-api-key"];
  checks.authentication = {
    status: hasAuth ? "Present" : "Not Detected",
    secure: response.config?.headers?.authorization?.startsWith("Bearer ")
      ? "Using Bearer token authentication"
      : "Review authentication method security",
  };

  checks.sensitiveDataExposure = analyzeSensitiveData(response.data);
  if (checks.sensitiveDataExposure.status !== "No obvious data exposure") {
    score -= 20;
    recommendations.push("Review response data for sensitive information exposure");
  }

  checks.injectionVulnerability = analyzeInjectionVulnerabilities(response.data);
  if (checks.injectionVulnerability.status !== "No obvious vulnerabilities") {
    score -= 25;
    recommendations.push("Review error handling to prevent information disclosure");
  }

  if (response.status >= 500) {
    score -= 15;
    recommendations.push("Server errors may expose sensitive information - implement proper error handling");
  }

  const infoHeaders = ["server", "x-powered-by", "x-aspnet-version"];
  infoHeaders.forEach((header) => {
    if (response.headers[header]) {
      score -= 5;
      recommendations.push(`Consider removing '${header}' header to reduce information disclosure`);
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
  const dataString = JSON.stringify(data).toLowerCase();
  const sensitivePatterns = [
    { pattern: /password/gi, type: "password" },
    { pattern: /secret/gi, type: "secret" },
    { pattern: /token/gi, type: "token" },
    { pattern: /api[_-]?key/gi, type: "api_key" },
    { pattern: /credit[_-]?card/gi, type: "credit_card" },
    { pattern: /ssn|social[_-]?security/gi, type: "ssn" },
    { pattern: /\b\d{4}[_-]?\d{4}[_-]?\d{4}[_-]?\d{4}\b/g, type: "card_number" },
    { pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, type: "email" },
  ];

  const foundPatterns = [];
  sensitivePatterns.forEach(({ pattern, type }) => {
    const matches = dataString.match(pattern);
    if (matches) {
      foundPatterns.push({ type, count: matches.length });
    }
  });

  return foundPatterns.length > 0
    ? { status: "Potential sensitive data detected", details: foundPatterns }
    : { status: "No obvious data exposure", details: "No sensitive data patterns detected in response" };
};

const analyzeInjectionVulnerabilities = (data) => {
  const dataString = JSON.stringify(data);
  const errorPatterns = [
    { pattern: /sql.*error/gi, type: "SQL Error" },
    { pattern: /mysql.*error/gi, type: "MySQL Error" },
    { pattern: /oracle.*error/gi, type: "Oracle Error" },
    { pattern: /postgresql.*error/gi, type: "PostgreSQL Error" },
    { pattern: /syntax.*error.*near/gi, type: "SQL Syntax Error" },
    { pattern: /warning.*mysql_/gi, type: "MySQL Warning" },
    { pattern: /fatal.*error/gi, type: "Fatal Error" },
    { pattern: /stack trace/gi, type: "Stack Trace" },
  ];

  const foundErrors = [];
  errorPatterns.forEach(({ pattern, type }) => {
    if (pattern.test(dataString)) {
      foundErrors.push(type);
    }
  });

  return foundErrors.length > 0
    ? { status: "Potential vulnerability indicators detected", details: foundErrors }
    : { status: "No obvious vulnerabilities", details: "No common error patterns detected in response" };
};

export const testApi = async (req, res) => {
  const { url, method, headers, body, options } = req.body;

  if (!url || !method) {
    return res.status(400).json({ error: "URL and method are required" });
  }

  const result = await testAPIWithSecurity(url, method, headers, body, options);

  if (result.error) {
    return res.status(500).json({ error: result.error });
  }

  try {
    const testResult = new apiTestModel({
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
    });
    await testResult.save();
  } catch (error) {
    console.error("Error saving test result:", error);
  }

  return res.status(200).json(result);
};