// import axios from 'axios';
import { Whois } from '../models/whoisModel.js';
import whois from 'whois'


export const getWhoisData = async (req, res) => {
  try {
    const { domain } = req.body;
    console.log(domain)
    if (!domain) {
      return res.status(400).json({ error: 'Domain is required' });
    }

    await whois.lookup(domain, async function (err, data) {

      if (err) {
        console.log("Error: ", err)
        res.status(500).json({ error: err });
      }

      const whoisEntry = new Whois({
        domain,
        ...data,
      });

      await whoisEntry.save();

      res.json({ data });
    })
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch WHOIS data' });
  }
};
