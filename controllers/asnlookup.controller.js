import ASNLookup from '../models/asnlookup.model.js';
import {getWhoisData} from './whoisController.js'
import fetch from 'node-fetch';

export const lookupASN = async (req, res) => {
  const { ip } = req.body;

  if (!ip) return res.status(400).json({ error: 'IP address is required' });

  try {
    // const response = await fetch(`https://ipapi.co/${ip}/json/`);
    const response = await fetch(`https://ipwho.is/${ip}`);
    const data = await response.json();
    console.log(data)

    if (data.error || !data.connection.asn) {
      return res.status(404).json({ error: 'ASN info not found for this IP' });
    }
    
    const asnNumber = "AS" + data.connection.asn.toString()
    // const newRecord = new ASNLookup({
    //   ip,
    //   asn: data.asn,
    //   name: data.org,
    //   country_code: data.country,
    //   description: data.org,
    //   registry: data.version === 4 ? 'IPv4' : 'IPv6',
    // });

    // await newRecord.save();
    // res.status(200).json({ asnInfo: newRecord });
    req.body.domain = asnNumber;
    console.log(req.body)
    getWhoisData(req, res)
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
};
