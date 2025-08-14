// controllers/portScanner.controller.js
import PortScan from "../models/portScan.model.js";

/* ---------------------- Deterministic RNG helpers ---------------------- */
const hashString = (s) => {
  let h = 2166136261 >>> 0; // FNV-1a
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
};
const mulberry32 = (seed) => {
  let t = seed >>> 0;
  return function () {
    t += 0x6D2B79F5;
    let r = Math.imul(t ^ (t >>> 15), 1 | t);
    r ^= r + Math.imul(r ^ (r >>> 7), 61 | r);
    return ((r ^ (r >>> 14)) >>> 0) / 4294967296;
  };
};

/* --------------------------- Port Scan (demo) --------------------------- */
const scanPorts = async (host, startPort, endPort) => {
  const ports = {};
  const total = endPort - startPort + 1;

  // deterministic “random” so same input -> same open/closed set
  const rand = mulberry32(hashString(`${host}|${startPort}|${endPort}`));

  let openCount = 0;
  for (let port = startPort; port <= endPort; port++) {
    const open = rand() < 0.2; // 20% open for demo
    if (open) openCount++;

    ports[port] = {
      port,
      open,
      service: open ? `Service ${port}` : "Unknown",
      risk: open ? (port % 2 === 0 ? "High" : "Low") : "None",
      description: open
        ? `Port ${port} is open and running a service.`
        : `Port ${port} is closed.`,
    };
  }

  let riskAssessment = "Low";
  if (openCount > total * 0.3) riskAssessment = "High";
  else if (openCount > total * 0.1) riskAssessment = "Medium";

  const recommendations = [];
  if (riskAssessment === "High") recommendations.push("Close unused open ports immediately.");
  else if (riskAssessment === "Medium") recommendations.push("Monitor open ports regularly.");

  const openPorts = Object.values(ports).filter((p) => p.open).map((p) => p.port);
  const suspicious = Object.values(ports).filter((p) => p.open && p.risk === "High").map((p) => p.port);

  return { ports, total, openCount, openPorts, suspicious, riskAssessment, recommendations };
};

export const portScanHandler = async (req, res) => {
  try {
    const { host } = req.query;
    let { startPort, endPort, port } = req.query;
    if (!host) return res.status(400).json({ error: "Host is required" });

    // Normalize inputs
    const asInt = (v) => (v === undefined ? NaN : parseInt(String(v).trim(), 10));
    let start, end;

    if (startPort !== undefined || endPort !== undefined) {
      // explicit range wins
      start = asInt(startPort ?? "1");
      end   = asInt(endPort ?? String(start));
    } else if (port !== undefined) {
      const p = String(port).trim();
      // Accept "60-2000" in the 'port' param as a range (fallback)
      const m = p.match(/^(\d{1,5})\s*-\s*(\d{1,5})$/);
      if (m) {
        start = asInt(m[1]);
        end   = asInt(m[2]);
      } else {
        // single port
        start = asInt(p);
        end   = asInt(p);
      }
    } else {
      start = 1; end = 1024; // default small range
    }

    if (isNaN(start) || isNaN(end) || start < 1 || end > 65535 || start > end) {
      return res.status(400).json({ error: "Invalid port range" });
    }

    const maxRange = 10000;
    if (end - start + 1 > maxRange) {
      return res.status(400).json({ error: `Port range too large. Max ${maxRange} ports allowed.` });
    }

    const scanData = await scanPorts(host, start, end);

    // Save (optional) – we intentionally DO NOT return scanTime
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

    return res.json({
      host,
      ports: scanData.ports,         // ALL ports in the range
      openPorts: scanData.openPorts,
      suspicious: scanData.suspicious,
      summary: scanResult.summary,   // no scanTime field
      recommendations: scanData.recommendations,
    });
  } catch (error) {
    console.error("Scan error:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
};


/* ------------------------------ ASN ------------------------------ */
const asnNum = (v) => String(v).replace(/^AS/i, "").trim();

export const asnOverviewHandler = async (req, res) => {
  try {
    const asn = asnNum(req.params.asn);
    const [infoRes, pfxRes, peersRes] = await Promise.all([
      fetch(`https://api.bgpview.io/asn/${asn}`),
      fetch(`https://api.bgpview.io/asn/${asn}/prefixes`),
      fetch(`https://api.bgpview.io/asn/${asn}/peers`),
    ]);

    const info = await infoRes.json();
    const pfx = await pfxRes.json();
    const peers = await peersRes.json();

    return res.json({
      asn: `AS${asn}`,
      name: info?.data?.name,
      description: info?.data?.description_short || info?.data?.description_full,
      country_code: info?.data?.country_code,
      rir_allocation: info?.data?.rir_allocation,
      prefixes_v4: pfx?.data?.ipv4_prefixes || [],
      prefixes_v6: pfx?.data?.ipv6_prefixes || [],
      peers_v4: peers?.data?.ipv4_peers || [],
      peers_v6: peers?.data?.ipv6_peers || [],
    });
  } catch (e) {
    console.error("ASN overview error:", e);
    return res.status(500).json({ error: "Failed to fetch ASN overview." });
  }
};

export const asnDomainsHandler = async (req, res) => {
  const asn = asnNum(req.params.asn);
  const limit = Math.min(parseInt(req.query.limit || "100", 10), 500);

  try {
    const key = process.env.SECURITYTRAILS_API_KEY;
    if (key) {
      const r = await fetch(`https://api.securitytrails.com/v1/as/${asn}/domains?include_ips=true`, {
        headers: { Accept: "application/json", APIKEY: key },
      });
      if (!r.ok) throw new Error(`SecurityTrails HTTP ${r.status}`);
      const data = await r.json();
      const items = (data?.domains || []).slice(0, limit).map((d) => ({
        domain: d?.hostname || d?.domain || d,
        ips: d?.current_dns?.a?.values?.map((v) => v.ip) || d?.ips || [],
      }));
      return res.json({ asn: `AS${asn}`, count: items.length, domains: items });
    }

    // Fallback: prefix hints
    const pfxRes = await fetch(`https://api.bgpview.io/asn/${asn}/prefixes`);
    const pfx = await pfxRes.json();
    const top = (pfx?.data?.ipv4_prefixes || []).slice(0, 5);
    const samples = top
      .map((p) => ({ prefix: p.prefix, sample_hint: p?.ip || p?.prefix?.split("/")[0] }))
      .filter(Boolean);

    return res.json({
      asn: `AS${asn}`,
      note: "For full domain enumeration, set SECURITYTRAILS_API_KEY. Current response contains prefix-based hints.",
      domains: samples.slice(0, limit),
    });
  } catch (e) {
    console.error("ASN domains error:", e);
    return res.status(500).json({ error: "Failed to fetch associated domains." });
  }
};

/* ------------------------------ CSV export ------------------------------ */
const toCsv = (rows) => {
  if (!rows?.length) return "";
  const headers = Object.keys(rows[0]);
  const lines = [headers.join(",")];
  for (const r of rows) lines.push(headers.map((h) => JSON.stringify(r[h] ?? "")).join(","));
  return lines.join("\n");
};

export const exportCsvHandler = async (req, res) => {
  try {
    const { filename = "export.csv", rows = [] } =
      (req.body && typeof req.body === "object") ? req.body : {};
    const csv = toCsv(rows);
    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    return res.send(csv);
  } catch (e) {
    console.error("CSV export error:", e);
    return res.status(500).json({ error: "Failed to export CSV." });
  }
};
