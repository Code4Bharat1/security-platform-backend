import { exec } from "child_process";

export const scanRogueWifi = (req, res) => {
  exec("iwlist scan | grep 'ESSID'", (err, stdout, stderr) => {
    if (err || stderr) {
      return res.status(500).json({ error: "WiFi scan failed." });
    }

    const ssids = stdout
      .split("\n")
      .map((line) => line.match(/ESSID:"(.+?)"/)?.[1])
      .filter(Boolean);

    const count = {};
    const duplicates = [];

    ssids.forEach((ssid) => {
      count[ssid] = (count[ssid] || 0) + 1;
      if (count[ssid] === 2) duplicates.push(ssid);
    });

    if (duplicates.length > 0) {
      return res.json({
        status: "⚠️ Rogue WiFi Detected!",
        duplicates,
        message: `Duplicate SSIDs found: ${duplicates.join(", ")}`,
      });
    } else {
      return res.json({
        status: "✅ Safe",
        message: "No rogue WiFi networks found.",
      });
    }
  });
};
