import dns from 'dns/promises';
import ReverseDNS from '../models/ReverseDNS.js';

export const reverseDNSLookup = async (req, res) => {
  const { ip } = req.body;

  if (!ip) return res.status(400).json({ error: 'IP address is required' });
            
  try {
    const startTime = Date.now();
    // Lookup PTR records
    const domains = await dns.reverse(ip);
     const timespan = Date.now() - startTime;

    // Save or update in DB
    const doc = await ReverseDNS.findOneAndUpdate(
      { ip },
      { domains, lookedUpAt: new Date(), timespan },
      { upsert: true, new: true }
    );

    res.json({ domains: doc.domains });
  } catch (error) {
     console.error('Reverse DNS Lookup Failed:', error.message);
    // If no PTR record or invalid IP, dns.reverse throws
    res.status(200).json({ domains: [], error: 'No PTR record found or invalid IP' });
  }
};
