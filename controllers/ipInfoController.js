import fetch from 'node-fetch';
import ipaddr from 'ipaddr.js';
import winston from 'winston';

const logger = winston.createLogger({
  level: process.env.NODE_ENV === 'production' ? 'error' : 'debug',
  transports: [ new winston.transports.Console() ]
});

// ✅ Main Controller
export const getIpInfo = async (req, res) => {
  const { ip } = req.body;

  if (!ip || !ipaddr.isValid(ip)) {
    return res.status(400).json({ error: "A valid IP address is required." });
  }

  console.log("🔥 Route hit with IP:", ip);

  try {
    // 1. IP Info (Location, ISP etc)
    const ipwhoRes = await fetch(`https://ipwho.is/${ip}`);
    const ipwhoData = await ipwhoRes.json();

    // 2. AbuseIPDB (Threat Intelligence)
    const abuseRes = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`, {
      headers: { "Key": process.env.ABUSEIPDB_KEY, "Accept": "application/json" }
    });
    const abuseData = await abuseRes.json();

    // ✅ Response format (same as image)
    const report = {
      reportGeneratedAt: new Date().toLocaleString(),
      basicInformation: {
        ipAddress: ipwhoData.ip ?? "N/A",
        version: ipaddr.parse(ip).kind().toUpperCase(),
        reverseDNS: ipwhoData.reverse ?? "N/A",
        hostname: ipwhoData.connection?.org ?? "N/A"
      },
      locationData: {
        country: ipwhoData.country ?? "N/A",
        region: ipwhoData.region ?? "N/A",
        city: ipwhoData.city ?? "N/A",
        timezone: ipwhoData.timezone?.id ?? "N/A",
        latitude: ipwhoData.latitude ?? "N/A",
        longitude: ipwhoData.longitude ?? "N/A",
      },
      networkDetails: {
        isp: ipwhoData.connection?.isp ?? "N/A",
        organization: ipwhoData.connection?.org ?? "N/A",
        asn: ipwhoData.connection?.asn ?? "N/A",
        asType: ipwhoData.connection?.type ?? "N/A",
        cidrRange: ipwhoData.connection?.range ?? "N/A"
      },
      securityThreatIntel: {
        proxyOrVpn: ipwhoData.security?.proxy ? "Yes" : "No",
        torExitNode: ipwhoData.security?.tor ? "Yes" : "No",
        blacklistStatus: abuseData?.data?.abuseConfidenceScore > 0 ? "Listed" : "Not Listed",
        malwareHostingHistory: abuseData?.data?.totalReports > 0 ? "Detected" : "None Detected",
        spamReports: abuseData?.data?.totalReports ?? 0
      }
    };

    return res.json(report);

  } catch (error) {
    logger.error(`Fetch error: ${error.message}`, { error });
    res.status(500).json({ error: "Server error while fetching IP info." });
  }
};
