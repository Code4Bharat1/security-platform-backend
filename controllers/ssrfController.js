// controllers/ssrfController.js
import fetch from 'node-fetch';
import { SSRFResult } from '../models/ssrfResultModel.js';

const commonPayloads = [
  'http://localhost',
  'http://127.0.0.1',
  'http://169.254.169.254',
  'http://0.0.0.0',
  'http://[::1]',
];

export const testSSRF = async (req, res) => {
  try {
    const { targetUrl } = req.body;
    if (!targetUrl || !targetUrl.startsWith('http')) {
      return res.status(400).json({ error: 'Valid targetUrl required' });
    }

    const results = [];
    for (const payload of commonPayloads) {
      try {
        const response = await fetch(`${targetUrl}?url=${encodeURIComponent(payload)}`, {
          timeout: 8000
        });
        const body = await response.text();
        const snippet = body.substring(0, 200);
        const isVulnerable = response.status === 200 && /EC2|metadata|root|127|localhost/i.test(body);

        results.push({
          payload,
          statusCode: response.status || 'ERROR',
          bodySnippet: snippet,
          vulnerable :isVulnerable,
        });
      } catch (err) {
        results.push({
          payload,
          statusCode: 'ERROR',
          bodySnippet: err.message,
          isVulnerable: false
        });
      }
    }

    await SSRFResult.create({
      targetUrl,
      payloadsTested: commonPayloads,
      results
    });

    res.json({ results });
  } catch (err) {
    res.status(500).json({ error: 'SSRF testing failed', details: err.message });
  }
};

export const getSSRFScanHistory = async (req, res) => {
  try {
    const scans = await SSRFResult.find().sort({ createdAt: -1 }).limit(20);
    res.json({ scans });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch history' });
  }
};

export const deleteSSRFScan = async (req, res) => {
  try {
    const { id } = req.params;
    const result = await SSRFResult.findByIdAndDelete(id);

    if (!result) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    res.json({ message: 'Scan deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete scan', details: err.message });
  }
};
