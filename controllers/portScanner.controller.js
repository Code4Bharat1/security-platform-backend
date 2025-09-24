// controllers/portScanner.controller.js
import PortScan from "../models/portScan.model.js";
import dns from 'dns';
import { promisify } from 'util';

const dnsLookup = promisify(dns.lookup);
const dnsReverse = promisify(dns.reverse);

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

/* ---------------------- Common port services mapping ---------------------- */
const getCommonServiceName = (port) => {
  const services = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    993: 'IMAPS',
    995: 'POP3S',
    3389: 'RDP',
    5432: 'PostgreSQL',
    3306: 'MySQL',
    6379: 'Redis',
    27017: 'MongoDB',
    8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt',
    9200: 'Elasticsearch',
    5984: 'CouchDB'
  };
  return services[port] || `Service ${port}`;
};

/* ---------------------- Hostname resolution ---------------------- */
const resolveHostname = async (host, port) => {
  try {
    // If host is already an IP, try reverse DNS
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    if (ipRegex.test(host)) {
      try {
        const hostnames = await dnsReverse(host);
        return hostnames[0] || null;
      } catch {
        return null;
      }
    } else {
      // If host is a domain, return it as is (it's already a hostname)
      return host;
    }
  } catch (error) {
    console.log(`Failed to resolve hostname for ${host}:${port}`, error.message);
    return null;
  }
};

/* --------------------------- Enhanced Port Scan --------------------------- */
const scanPorts = async (host, startPort, endPort, includeHostnames = false) => {
  const ports = {};
  const total = endPort - startPort + 1;

  // Deterministic "random" so same input -> same open/closed set
  const rand = mulberry32(hashString(`${host}|${startPort}|${endPort}`));

  let openCount = 0;
  const portArray = [];

  // First pass: determine open/closed status
  for (let port = startPort; port <= endPort; port++) {
    const open = rand() < 0.2; // 20% open for demo
    if (open) openCount++;

    const serviceType = getCommonServiceName(port);
    const riskLevel = open ? (port % 2 === 0 ? "High" : "Low") : "None";

    portArray.push({
      port,
      open,
      service: open ? serviceType : "Closed",
      risk: riskLevel,
      description: open
        ? `Port ${port} is open and running ${serviceType}.`
        : `Port ${port} is closed.`,
      hostname: null // Will be populated if requested
    });
  }

  // Second pass: resolve hostnames for open ports if requested
  if (includeHostnames) {
    const openPorts = portArray.filter(p => p.open);
    const hostnamePromises = openPorts.map(async (portInfo) => {
      const hostname = await resolveHostname(host, portInfo.port);
      portInfo.hostname = hostname;
      return portInfo;
    });
    
    await Promise.all(hostnamePromises);
  }

  // Convert to object format for backward compatibility
  portArray.forEach(portInfo => {
    ports[portInfo.port] = portInfo;
  });

  // Risk assessment
  let riskAssessment = "Low";
  if (openCount > total * 0.3) riskAssessment = "High";
  else if (openCount > total * 0.1) riskAssessment = "Medium";

  const recommendations = [];
  if (riskAssessment === "High") {
    recommendations.push("Close unused open ports immediately.");
    recommendations.push("Implement firewall rules to restrict access.");
  } else if (riskAssessment === "Medium") {
    recommendations.push("Monitor open ports regularly.");
    recommendations.push("Ensure only necessary services are running.");
  }

  const openPorts = portArray.filter((p) => p.open).map((p) => p.port);
  const suspicious = portArray.filter((p) => p.open && p.risk === "High").map((p) => p.port);

  return { 
    ports, 
    portArray, // Include array format for easier filtering
    total, 
    openCount, 
    openPorts, 
    suspicious, 
    riskAssessment, 
    recommendations 
  };
};

/* ---------------------- Apply filters to port results ---------------------- */
const applyPortFilter = (portArray, filter) => {
  switch (filter?.toLowerCase()) {
    case 'open':
      return portArray.filter(p => p.open);
    case 'closed':
      return portArray.filter(p => !p.open);
    case 'all':
    default:
      return portArray;
  }
};

export const portScanHandler = async (req, res) => {
  try {
    const { host, filter = 'all', includeHostnames = 'false' } = req.query;
    let { startPort, endPort, port } = req.query;
    
    if (!host) {
      return res.status(400).json({ 
        error: "Host is required",
        message: "Please provide a host parameter (IP address or domain name)" 
      });
    }

    // Validate filter parameter
    const validFilters = ['all', 'open', 'closed'];
    if (!validFilters.includes(filter.toLowerCase())) {
      return res.status(400).json({
        error: "Invalid filter parameter",
        message: `Filter must be one of: ${validFilters.join(', ')}`
      });
    }

    const shouldIncludeHostnames = includeHostnames.toLowerCase() === 'true';

    // Normalize inputs
    const asInt = (v) => (v === undefined ? NaN : parseInt(String(v).trim(), 10));
    let start, end;

    if (startPort !== undefined || endPort !== undefined) {
      // Explicit range wins
      start = asInt(startPort ?? "1");
      end = asInt(endPort ?? String(start));
    } else if (port !== undefined) {
      const p = String(port).trim();
      // Accept "60-2000" in the 'port' param as a range (fallback)
      const m = p.match(/^(\d{1,5})\s*-\s*(\d{1,5})$/);
      if (m) {
        start = asInt(m[1]);
        end = asInt(m[2]);
      } else {
        // Single port
        start = asInt(p);
        end = asInt(p);
      }
    } else {
      start = 1; 
      end = 1024; // Default small range
    }

    if (isNaN(start) || isNaN(end) || start < 1 || end > 65535 || start > end) {
      return res.status(400).json({ 
        error: "Invalid port range",
        message: "Port range must be between 1-65535 and start port must be less than or equal to end port"
      });
    }

    const maxRange = 10000;
    if (end - start + 1 > maxRange) {
      return res.status(400).json({ 
        error: `Port range too large. Max ${maxRange} ports allowed.`,
        message: `Requested range: ${end - start + 1} ports. Please reduce the range.`
      });
    }

    console.log(`Scanning ${host} ports ${start}-${end} with filter: ${filter}`);

    const scanData = await scanPorts(host, start, end, shouldIncludeHostnames);

    // Apply filtering
    const filteredPorts = applyPortFilter(scanData.portArray, filter);
    
    // Convert filtered results back to object format for backward compatibility
    const filteredPortsObject = {};
    filteredPorts.forEach(portInfo => {
      filteredPortsObject[portInfo.port] = portInfo;
    });

    // Calculate filtered statistics
    const filteredOpenPorts = filteredPorts.filter(p => p.open).map(p => p.port);
    const filteredSuspicious = filteredPorts.filter(p => p.open && p.risk === "High").map(p => p.port);

    // Save scan result (optional) – we intentionally DO NOT return scanTime
    const scanResult = new PortScan({
      host,
      ports: scanData.ports, // Save all ports, not just filtered
      summary: {
        total: scanData.total,
        open: scanData.openCount,
        riskAssessment: scanData.riskAssessment,
      },
      recommendations: scanData.recommendations,
      metadata: {
        filter: filter,
        includeHostnames: shouldIncludeHostnames,
        portRange: `${start}-${end}`
      }
    });
    
    await scanResult.save();

    return res.json({
      host,
      filter: filter,
      includeHostnames: shouldIncludeHostnames,
      portRange: `${start}-${end}`,
      ports: filteredPortsObject, // Filtered ports in object format
      portList: filteredPorts,    // Filtered ports in array format for easier frontend handling
      openPorts: filteredOpenPorts,
      suspicious: filteredSuspicious,
      summary: {
        total: scanData.total,
        open: scanData.openCount,
        filtered: filteredPorts.length,
        riskAssessment: scanData.riskAssessment,
      },
      recommendations: scanData.recommendations,
    });
    
  } catch (error) {
    console.error("Scan error:", error);
    return res.status(500).json({ 
      error: "Internal server error",
      message: "An error occurred while scanning ports. Please try again."
    });
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