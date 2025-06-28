// controllers/ipInfoController.js
import fetch from 'node-fetch'; // Use this if Node < 18

export const getIpInfo = async (req, res) => {
  const { ip } = req.body;

  if (!ip) {
    return res.status(400).json({ success: false, message: "❌ IP address is required." });
  }

  try {
    const response = await fetch(`https://ipapi.co/${ip}/json/`);
    const data = await response.json();

    if (data.error) {
      return res.status(404).json({ success: false, message: "❌ Invalid IP address." });
    }

    res.status(200).json({
      success: true,
      data: {
        ip: data.ip,
        city: data.city,
        region: data.region,
        country: data.country_name,
        postal: data.postal,
        timezone: data.timezone,
        org: data.org,
        asn: data.asn
      }
    });
  } catch (err) {
    console.error("IP Lookup Error:", err);
    res.status(500).json({ success: false, message: "❌ Server error while fetching IP info." });
  }
};
