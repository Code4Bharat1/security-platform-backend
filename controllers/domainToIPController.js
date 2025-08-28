import Domain from '../models/dnsModel.js';
import dns from 'dns';

export const convertDomainToIP = async (req, res) => {
  const { domain } = req.body;

  if (!domain) {
    return res.status(400).json({ message: 'Domain is required' });
  }

  try {
    dns.lookup(domain, async (err, address) => {
      if (err) {
        return res.status(500).json({ message: 'Error resolving domain' });
      }

      const result = {
        domain,
        ip: address,
        timestamp: new Date(),
      };

      // Save the result in the database
      await Domain.create(result);

      res.status(200).json({ domain, ip: address });
    });
  } catch (error) {
    res.status(500).json({ message: 'Something went wrong' });
  }
};
