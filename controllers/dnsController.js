// controllers/dnsController.js
import fetch from 'node-fetch';
import DNSLog from '../models/dnsModel.js';

export const resolveDNS = async (req, res) => {
  const { domain, type = 'A' } = req.body;

  if (!domain) {
    return res.status(400).json({ success: false, error: 'Domain is required' });
  }

  try {
    const response = await fetch(`https://dns.google/resolve?name=${domain}&type=${type}`);
    const data = await response.json();

    // Optional: Save the lookup to MongoDB
    await DNSLog.create({ domain, type, result: data });

    return res.status(200).json({ success: true, data });
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
};
