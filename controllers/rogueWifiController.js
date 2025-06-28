import RogueWiFi from "../models/RogueWiFi.js";

const suspiciousSSIDs = ["FreeWiFi", "OpenNet", "PublicNetwork"];
const rogueIPs = ["192.168.0.100", "10.0.0.66"];

export const scanRogueWiFi = async (req, res) => {
  const { input } = req.body;

  let status = "safe";
  let message = "No suspicious activity detected.";

  if (suspiciousSSIDs.includes(input)) {
    status = "suspicious";
    message = "This SSID is commonly used in rogue networks.";
  } else if (rogueIPs.includes(input)) {
    status = "rogue";
    message = "This IP is flagged as a rogue access point.";
  }

  const result = new RogueWiFi({ input, status, message });
  await result.save();

  res.json({ input, status, message, savedAt: result.timestamp });
};
