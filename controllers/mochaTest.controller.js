import fetch from 'node-fetch';
import MochaTest from '../models/mochaTest.model.js';

export const runMochaTest = async (req, res) => {
  const { endpoint, method, headers, body, testDescription, timeoutMs = 10000, wantPrevious = false } = req.body;

  try {
    // Validate URL format
    let validatedUrl;
    try {
      validatedUrl = new URL(endpoint);
      if (!['http:', 'https:'].includes(validatedUrl.protocol)) {
        throw new Error('URL must use HTTP or HTTPS protocol');
      }
    } catch (urlError) {
      return res.status(400).json({ error: `Invalid URL format: ${urlError.message}` });
    }

    // Fetch previous record BEFORE running new test (for comparison)
    let previousDuration = null;
    if (wantPrevious) {
      const prev = await MochaTest.findOne({ endpoint, method }).sort({ _id: -1 }).lean();
      if (prev && typeof prev.duration === 'number') previousDuration = prev.duration;
    }

    const start = Date.now();

    // Prepare fetch options
    const fetchOptions = {
      method: method || 'GET',
      headers: headers || {},
    };

    if (method !== 'GET' && body) {
      fetchOptions.body = JSON.stringify(body);
      if (!fetchOptions.headers['Content-Type'] && !fetchOptions.headers['content-type']) {
        fetchOptions.headers['Content-Type'] = 'application/json';
      }
    }

    // Timeout handling via AbortController
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), Math.max(1, Number(timeoutMs)));
    (fetchOptions).signal = controller.signal;

    let response;
    let responseBody;

    try {
      response = await fetch(endpoint, fetchOptions);
      clearTimeout(timer);

      const contentType = response.headers.get('content-type') || '';
      if (contentType.includes('application/json')) {
        responseBody = await response.json().catch(async () => {
          // rare: bad JSON while header says JSON
          const txt = await response.text().catch(() => '');
          try { return JSON.parse(txt); } catch { return { text: txt }; }
        });
      } else {
        const textResponse = await response.text();
        try {
          responseBody = JSON.parse(textResponse);
        } catch {
          responseBody = { text: textResponse };
        }
      }
    } catch (fetchError) {
      clearTimeout(timer);
      // Timeout
      if (fetchError.name === 'AbortError') {
        const duration = Date.now() - start;
        // Save as failed test (timeout)
        try {
          await MochaTest.create({
            endpoint, method, headers, body, testDescription,
            passed: false,
            assertions: [{ message: `Request timed out after ${timeoutMs}ms`, passed: false }],
            response: { error: `Timeout after ${timeoutMs}ms` },
            duration
          });
        } catch {}
        return res.status(504).json({ error: `Request timed out after ${timeoutMs}ms`, duration, statusCode: 504 });
      }
      // Network error
      const duration = Date.now() - start;
      try {
        await MochaTest.create({
          endpoint, method, headers, body, testDescription,
          passed: false,
          assertions: [{ message: `Network error: ${fetchError.message}`, passed: false }],
          response: { error: `Network error: ${fetchError.message}` },
          duration
        });
      } catch {}
      return res.status(500).json({ error: `Network error: ${fetchError.message}`, duration, statusCode: 500 });
    }

    const assertions = [];
    let passed = true;

    // Status code assertion
    if (response.status >= 200 && response.status < 300) {
      assertions.push({ message: `Status code is ${response.status} (Success)`, passed: true });
    } else {
      passed = false;
      assertions.push({
        message: `Expected 2xx but got ${response.status}`,
        passed: false,
        error: `HTTP ${response.status}: ${response.statusText || 'Error'}`
      });
    }

    // Response format assertion (informational)
    if (responseBody && typeof responseBody === 'object') {
      assertions.push({ message: 'Response is valid JSON object', passed: true });
    } else {
      assertions.push({ message: 'Response is not a JSON object', passed: true });
    }

    // Response time assertion (warning only)
    const duration = Date.now() - start;
    if (duration < 5000) {
      assertions.push({ message: `Response time is acceptable (${duration}ms)`, passed: true });
    } else {
      assertions.push({ message: `Response time is slow (${duration}ms)`, passed: true });
    }

    // Compute comparison deltas
    let deltaMs = 0;
    let deltaPct = 0;
    let degraded = false;
    if (typeof previousDuration === 'number') {
      deltaMs = duration - previousDuration;
      deltaPct = previousDuration === 0 ? 0 : Math.round((deltaMs / previousDuration) * 100);
      degraded = deltaMs > 0;
    }

    // Save in DB (do not fail test on DB errors)
    try {
      await MochaTest.create({
        endpoint, method, headers, body, testDescription,
        passed, assertions, response: responseBody, duration,
        // Optional: store comparison snapshot for history
        meta: { previousDuration, deltaMs, deltaPct, degraded }
      });
    } catch (dbError) {
      console.error('Database save error:', dbError);
    }

    res.json({
      passed,
      assertions,
      response: responseBody,
      duration,
      statusCode: response.status,
      // comparison extras
      previousDuration: typeof previousDuration === 'number' ? previousDuration : null,
      deltaMs,
      deltaPct,
      degraded
    });

  } catch (error) {
    console.error('Unexpected error:', error);
    res.status(500).json({
      error: `Unexpected error: ${error.message}`,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
};
