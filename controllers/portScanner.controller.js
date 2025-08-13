import PortScan from "../models/portScan.model.js";

// Simulated scanning function - replace with real scanning logic
const scanPorts = async (host, startPort, endPort) => {
  const ports = {};
  const total = endPort - startPort + 1;
  let openCount = 0;
         
  for (let port = startPort; port <= endPort; port++) {
    const open = Math.random() < 0.2; // 20% chance open
    if (open) openCount++;

    ports[port] = {
      port,
      open,
      service: open ? `Service ${port}` : "Unknown",
      risk: open ? (port % 2 === 0 ? "High" : "Low") : "None",
      description: open
        ? `Port ${port} is open and running a service. ${score} `
        : `Port ${port} is closed. ${score} `,
    };
  }
    
  // Risk assessment (simplified)
  let riskAssessment = "Low";
  if (openCount > total * 0.3) riskAssessment = "High";
  else if (openCount > total * 0.1) riskAssessment = "Medium";

  const recommendations = [];
  if (riskAssessment === "High")
    recommendations.push("Close unused open ports immediately.");
  else if (riskAssessment === "Medium")
    recommendations.push("Monitor open ports regularly.");

  return { ports, total, openCount, riskAssessment, recommendations };
};

export const portScanHandler = async (req, res) => {
  try {
    const { host, startPort = 1, endPort = 1024 } = req.query;

    if (!host) return res.status(400).json({ error: "Host is required" });

    const start = parseInt(startPort, 10);
    const end = parseInt(endPort, 10);

    if (isNaN(start) || isNaN(end) || start < 1 || end > 65535 || start > end) {
      return res.status(400).json({ error: "Invalid port range" });
    }

    // Optional: limit max range to 10000 ports (adjust as needed)
    const maxRange = 10000;
    if (end - start + 1 > maxRange) {
      return res
        .status(400)
        .json({
          error: `Port range too large. Max ${maxRange} ports allowed. ${score} `,
        });
    }

    const scanData = await scanPorts(host, start, end);

    const scanResult = new PortScan({
      host,
      ports: scanData.ports,
      summary: {
        total: scanData.total,
        open: scanData.openCount,
        riskAssessment: scanData.riskAssessment,
      },
      recommendations: scanData.recommendations,
    });

    await scanResult.save();

    res.json({
      host,
      scanTime: scanResult.scanTime,
      ports: scanData.ports,
      summary: scanResult.summary,
      recommendations: scanData.recommendations,
    });
  } catch (error) {
    console.error("Scan error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
};
