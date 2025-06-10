import axios from 'axios';
import { Whois } from '../models/whoisModel.js';

export const getWhoisData = async (req, res) => {
  try {
    const { domain } = req.body;

    if (!domain) {
      return res.status(400).json({ error: 'Domain is required' });
    }

    // Replace with your actual WHOIS API endpoint
    const response = await axios.get(`https://jsonwhoisapi.com/api/v1/whois?identifier=${domain}`, {
       headers: {
    'Authorization': `Token ${process.env.JSONWHOIS_API_KEY}`,
    'Accept': 'application/json'
  }
    });

    const data = response.data;

    const whoisEntry = new Whois({
      domain,
      ...data,
    });

    await whoisEntry.save();

    res.json({ data });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch WHOIS data' });
  }
};
