// import { Whois } from '../models/whoisModel.js';
import whois from 'whois';

export const getWhoisData = async (req, res) => {
  try {
    const { domain } = req.body;
    console.log(domain)
    if (!domain) {
      return res.status(400).json({ error: 'Domain is required' });
    }

    // ✅ whois-json async call, directly await
    const data = await whois.lookup(domain, (err, data) => {
      if (err) {
        return res.status(500).json({ error: 'WHOIS lookup failed' });
      }
      return res.status(200).json({ data: data });

    });

    // // ✅ Save in DB
    // const whoisEntry = new Whois({
    //   domain,
    //   data,
    // });
    // await whoisEntry.save();

  } catch (err) {
    console.error('WHOIS error:', err);
    res.status(500).json({ error: 'Failed to fetch WHOIS data' });
  }
};
