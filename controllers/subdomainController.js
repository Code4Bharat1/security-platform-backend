import { SubdomainResult } from '../models/subdomainModel.js';
import axios from 'axios';

export const findSubdomains = async (req, res) => {
  const { domain } = req.body;
  const API_KEY = process.env.SECURITYTRAILS_API_KEY;
  console.log("Loaded API key:", API_KEY);

  if (!domain) {
    return res.status(400).json({ error: 'Domain is required.' });
  }
  try {
    // External API or mocked results
    const response = await axios.get(`https://api.securitytrails.com/v1/domain/${domain}/subdomains`, {
      headers: {
        'APIKEY': API_KEY
      },
      timeout: 10000, // 10 seconds timeout
    });

    const subdomains = response.data.subdomains;

    if (!Array.isArray(subdomains) || subdomains.length === 0) {
      return res.status(200).json({ results: [] });
    }

    // Optional: Save to DB
    const saved = await SubdomainResult.create({
      domain,
      results: subdomains.map((s) => ({ subdomain: s })),
      timestamp: new Date(),
    });

    return res.status(200).json({ results: saved.results });
  }

  catch (error) {
    console.error('❌ Subdomain enumeration error:', error.message);
    if (error.response) {
      console.error('❌ API Error response:', error.response.status, error.response.data);
    } else if (error.request) {
      console.error('❌ No response received:', error.request);
    } else {
      console.error('❌ Error setting up request:', error.message);
    }

    return res.status(500).json({ error: 'Failed to fetch subdomains.' });
  }
};
