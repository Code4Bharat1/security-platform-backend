// routes/network.routes.js
import { Router } from "express";
import {
  portScanHandler,
  asnOverviewHandler,
  asnDomainsHandler,
  exportCsvHandler,
} from "../controllers/portScanner.controller.js";

const r = Router();

// Port scanning
r.get("/port-scan", portScanHandler);

// ASN info
r.get("/asn/:asn", asnOverviewHandler);
r.get("/asn/:asn/domains", asnDomainsHandler);

r.get("/portScan", portScanHandler);
r.get("/portscan", portScanHandler);

// CSV export
r.post("/export/csv", exportCsvHandler);

export default r;
