// controllers/thirdPartyPermissionController.js
import ThirdPartyScan from "../models/thirdPartyScan.model.js";

export const scanAppPermissions = async (req, res) => {
  try {
    const { appName } = req.body;

    if (!appName) {
      return res.status(400).json({ error: "App name is required." });
    }

    // Simulated risky and app permissions
    const riskyPermissions = [
      "READ_SMS",
      "WRITE_SMS",
      "READ_CALL_LOG",
      "RECORD_AUDIO",
      "ACCESS_FINE_LOCATION",
      "READ_CONTACTS",
      "WRITE_CONTACTS",
      "SYSTEM_ALERT_WINDOW",
    ];

    const appPermissions = [
      "INTERNET",
      "ACCESS_FINE_LOCATION",
      "READ_CONTACTS",
      "CAMERA",
    ];

    const riskyDetected = appPermissions.filter((perm) =>
      riskyPermissions.includes(perm)
    );

    const message =
      riskyDetected.length > 0
        ? `⚠️ ${riskyDetected.length} risky permissions detected.`
        : "✅ No risky permissions found.";

    // Save to MongoDB
    const newScan = new ThirdPartyScan({
      appName,
      permissions: appPermissions,
      risky: riskyDetected,
      resultMessage: message,
    });

    await newScan.save();

    res.json({
      appName,
      permissions: appPermissions,
      risky: riskyDetected,
      message,
    });
  } catch (err) {
    console.error("Permission scan failed:", err.message);
    res.status(500).json({ error: "Server error" });
  }
};
