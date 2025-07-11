import express from 'express';
import fetch from 'node-fetch';
import ipaddr from 'ipaddr.js';
import winston from 'winston';
//import './routers/ipInfoRouter.js';

const logger = winston.createLogger({
  level: process.env.NODE_ENV === 'production' ? 'error' : 'debug',
  transports: [
    new winston.transports.Console()
  ]
});


export const getIpInfo = async (req, res) => {
  const { ip } = req.body;

  // Use ipaddr.js for robust IP address validation (IPv4 and IPv6)
  if (!ip || !ipaddr.isValid(ip)) {
    return res.status(400).json({ error: "A valid IP address is required." });
  }
  console.log("🔥 Route hit with IP:", req.body.ip);

  try {
    const response = await fetch(`https://ipwho.is/${ip}`);
    // const response = await fetch(`https://ipapi.co/${ip}/json/`);
    const data = await response.json();
    
    if (!response.ok || data.error) {
      return res.status(404).json({ error: "Invalid IP address or not found." });
    }

    res.json({
      ip: data.ip || "N/A",
      country: data.country_name || "N/A",
      city: data.city || "N/A",
      isp: data.org || "N/A",
      // org: data.org || "N/A", // Remove this line if org and isp are the same
      latitude: data.latitude || "N/A",
      longitude: data.longitude || "N/A",
    });
  } catch (error) {
    logger.error(`Fetch error: ${error.message}`, { error });
    res.status(500).json({ error: "Server error while fetching IP info." });
  }
};

//const PORT = process.env.PORT || 4180;

