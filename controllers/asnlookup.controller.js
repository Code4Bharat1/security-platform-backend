import ASNLookup from '../models/asnlookup.model.js';
import fetch from 'node-fetch';

export const lookupASN = async (req, res) => {
  const { ip } = req.body;

  if (!ip) return res.status(400).json({ error: 'IP address is required' });

  try {
    const response = await fetch(`https://ipapi.co/${ip}/json/`);
    const data = await response.json();

    if (data.error || !data.asn) {
      return res.status(404).json({ error: 'ASN info not found for this IP' });
    }
    console.log(data.asn)
    const newRecord = new ASNLookup({
      ip,
      asn: data.asn,
      name: data.org,
      country_code: data.country,
      description: data.org,
      registry: data.version === 4 ? 'IPv4' : 'IPv6',
    });

    await newRecord.save();

    res.status(200).json({ asnInfo: newRecord });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
};
