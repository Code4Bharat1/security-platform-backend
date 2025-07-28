import { Whois } from '../models/whoisModel.js';
import whois from 'whois-json';   // ✅ sirf ek import rakh

export const getWhoisData = async (req, res) => {
  try {
    const { domain } = req.body;

    if (!domain) {
      return res.status(400).json({ error: 'Domain is required' });
    }

    // ✅ whois-json async call, directly await
    const data = await whois(domain);

    // ✅ Save in DB
    const whoisEntry = new Whois({
      domain,
      ...data,
    });
    await whoisEntry.save();

    res.json({ data });

  } catch (err) {
    console.error('WHOIS error:', err);
    res.status(500).json({ error: 'Failed to fetch WHOIS data' });
  }
};
