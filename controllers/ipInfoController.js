import fetch from 'node-fetch';
import ipaddr from 'ipaddr.js';
import winston from 'winston';

const logger = winston.createLogger({
  level: process.env.NODE_ENV === 'production' ? 'error' : 'debug',
  transports: [ new winston.transports.Console() ]
});

export const getIpInfo = async (req, res) => {
  const { ip } = req.body;

  if (!ip || !ipaddr.isValid(ip)) {
    return res.status(400).json({ error: "A valid IP address is required." });
  }

  console.log("🔥 Route hit with IP:", ip);

  try {
    const response = await fetch(`https://ipwho.is/${ip}`);
    const data = await response.json();

    if (!response.ok || data.error) {
      return res.status(404).json({ error: "Invalid IP address or not found." });
    }

    res.json({
      ip: data.ip || "N/A",
      country: data.country || "N/A",
      city: data.city || "N/A",
      isp: data.connection?.isp || "N/A",
      org: data.connection?.org || "N/A",
      timezone: data.timezone?.id || "N/A",
      latitude: data.latitude || "N/A",
      longitude: data.longitude || "N/A",
    });
  } catch (error) {
    logger.error(`Fetch error: ${error.message}`, { error });
    res.status(500).json({ error: "Server error while fetching IP info." });
  }
};
