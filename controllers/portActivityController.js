import net from "net";
import PortScan from "../models/portScanModel.js";

export const scanPortActivity = async (req, res) => {
  const { ip } = req.body;

  if (!ip) {
    return res.status(400).json({ message: "IP address is required." });
  }

  const portsToScan = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389];
  const suspiciousPorts = [21, 23, 445, 3389];

  const openPorts = [];

  const checkPort = (port) =>
    new Promise((resolve) => {
      const socket = new net.Socket();
      let isOpen = false;

      socket.setTimeout(1000);

      socket.on("connect", () => {
        isOpen = true;
        socket.destroy();
      });

      socket.on("timeout", () => socket.destroy());
      socket.on("error", () => {});
      socket.on("close", () => resolve({ port, open: isOpen }));

      socket.connect(port, ip);
    });

  try {
    const results = await Promise.all(portsToScan.map(checkPort));
    const found = results.filter((r) => r.open).map((r) => r.port);

    const risky = found.filter((port) => suspiciousPorts.includes(port));

    await PortScan.create({
      ip,
      openPorts: found,
      riskyPorts: risky,
      scannedAt: new Date(),
    });

    res.json({
      ip,
      openPorts: found,
      riskyPorts: risky,
      message:
        risky.length > 0
          ? `⚠️ Suspicious ports found: ${risky.join(", ")}`
          : "✅ No suspicious ports detected.",
    });
  } catch (err) {
    res.status(500).json({ message: "Port scan failed.", error: err.message });
  }
};
