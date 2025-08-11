import PortScan from "../models/portScan.model.js";
import { execFile } from 'child_process';
import path from 'path'

// Simulated scanning function - replace with real scanning logic
const scanPorts = async (host, start, end) => {
  const total = end - start;
  const scriptPath = path.resolve('./scripts/portscan.py');

  return new Promise((resolve, reject) => {
    execFile('python', [scriptPath, host], { encoding: 'utf8' }, (error, stdout, stderr) => {
      if (error) {
        console.error('Port Scanner script error:', error);
        return reject({ status: 'error', message: error.message });
      }

      if (stderr) {
        console.warn('Port Scanner stderr:', stderr);
        // Optionally continue, depending on how critical stderr is
      }

      const generatedData = stdout.replaceAll("\r\n", "\n").trim();
      const openPortsList = generatedData
        .slice(generatedData.indexOf("[") + 1, generatedData.indexOf("]"))
        .split(",")
        .map(p => p.trim());

      const ports = {};
      let openCount = openPortsList.length;

      openPortsList.forEach((port) => {
        ports[port] = {
          port,
          service: `Service ${port}`,
          risk: (parseInt(port) % 2 === 0 ? "High" : "Low"),
          description: `Port ${port} is open and running a service.`,
        };
      });

      // Risk assessment (simplified)
      let riskAssessment = "Low";
      if (openCount > total * 0.3) riskAssessment = "High";
      else if (openCount > total * 0.1) riskAssessment = "Medium";

      const recommendations = [];
      if (riskAssessment === "High") {
        recommendations.push("Close unused open ports immediately.");
      } else if (riskAssessment === "Medium") {
        recommendations.push("Monitor open ports regularly.");
      }

      resolve({
        ports,
        total,
        openCount,
        riskAssessment,
        recommendations,
      });
    });
  });
};


export const portScanHandler = async (req, res) => {
  try {
    const host = req.query.host;
    console.log(host, !host)
    if (!host) {
      console.log(1)
      return res.status(400).json({ error: "No link, domain or ip provided" });}

    const start = 0;
    const end = 1024;

    if (isNaN(start) || isNaN(end) || start < 0 || end > 65535 || start > end) {
      return res.status(400).json({ error: "Invalid port range" });
    }

    // Optional: limit max range to 10000 ports (adjust as needed)
    const maxRange = 10000;
    if (end - start + 1 > maxRange) {
      return res
        .status(400)
        .json({
          error: `Port range too large. Max ${maxRange} ports allowed.`,
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