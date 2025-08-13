// controllers/subdomain.controller.js
import axios from 'axios';
import { SubdomainResult } from '../models/subdomainModel.js';

export const findSubdomains = async (req, res) => {
  const { domain } = req.body || {};
  const API_KEY = process.env.SECURITYTRAILS_API_KEY;

  if (!domain?.trim()) {
    return res.status(400).json({ error: 'Domain is required.' });
  }
  if (!API_KEY) {
    return res.status(500).json({ error: 'SecurityTrails API key is missing on the server.' });
  }

  const startedAt = new Date();

  try {
    const resp = await axios.get(
      `https://api.securitytrails.com/v1/domain/${domain}/subdomains`,
      {
        headers: { APIKEY: API_KEY },
        timeout: 15000,
      }
    );

    // SecurityTrails returns only labels; convert to FQDNs
    const labels = Array.isArray(resp.data?.subdomains) ? resp.data.subdomains : [];
    const fqdnList = [...new Set(labels.map(l => `${l}.${domain}`))].sort(); // uniq + sort

    const finishedAt = new Date();
    const durationMs = finishedAt - startedAt;

    // Persist (optional but you asked to keep your basic model, so just set the new fields)
    const saved = await SubdomainResult.create({
      domain: domain.trim().toLowerCase(),
      results: fqdnList.map(sub => ({ subdomain: sub })),
      total: fqdnList.length,
      startedAt,
      finishedAt,
      durationMs,
      timestamp: finishedAt,
    });

    return res.status(200).json({
      total: saved.total,
      startedAt: saved.startedAt,
      finishedAt: saved.finishedAt,
      durationMs: saved.durationMs,
      results: saved.results, // [{ subdomain }]
    });
  } catch (error) {
    const finishedAt = new Date();
    const durationMs = finishedAt - startedAt;

    // Helpful error messages
    if (error.response) {
      const { status, data } = error.response;

      // Common case: 401 when API key is invalid
      if (status === 401) {
        return res.status(502).json({
          error: 'Upstream 401 from SecurityTrails. Check your API key or account limits.',
          details: typeof data === 'string' ? data : (data?.message || data),
          startedAt,
          finishedAt,
          durationMs,
        });
      }

      return res.status(502).json({
        error: `Upstream error from SecurityTrails (status ${status}).`,
        details: typeof data === 'string' ? data : (data?.message || data),
        startedAt,
        finishedAt,
        durationMs,
      });
    }

    if (error.code === 'ECONNABORTED') {
      return res.status(504).json({
        error: 'SecurityTrails request timed out.',
        startedAt,
        finishedAt,
        durationMs,
      });
    }

    return res.status(500).json({
      error: 'Failed to fetch subdomains.',
      details: error.message,
      startedAt,
      finishedAt,
      durationMs,
    });
  }
};
