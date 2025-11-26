// models/scanResultModel.js
import mongoose from 'mongoose';

const vulnerabilitySchema = new mongoose.Schema({
  type: String,
  severity: String,
  description: String,
  details: String,
  recommendation: String,
  impact: String, // ✅ NEW: For port scanning impact
  wafDetails: mongoose.Schema.Types.Mixed, // ✅ NEW: For firewall details
}, { _id: false });

const scanResultSchema = new mongoose.Schema({
  // ==================== CORE FIELDS ====================
  domain: { type: String, required: true, index: true },
  timestamp: { type: Date, default: Date.now, index: true },
  scannerVersion: { type: String, default: '1.0.0' },
  scanId: { type: String, index: true },

  // ==================== EXISTING FEATURES ====================
  ssl: mongoose.Schema.Types.Mixed,
  headers: {
    type: Object,
    default: {},
  },
  vulnerabilities: [vulnerabilitySchema],
  vulnerabilityCount: { type: Number, default: 0 },
  vulnerabilityBreakdown: {
    critical: { type: Number, default: 0 },
    high: { type: Number, default: 0 },
    medium: { type: Number, default: 0 },
    low: { type: Number, default: 0 },
    info: { type: Number, default: 0 },
  },
  riskLevel: { type: String, default: 'low' },
  securityGrade: String,
  timespan: { type: Number, default: 0 },
  sitemap: mongoose.Schema.Types.Mixed,
  robots: mongoose.Schema.Types.Mixed,
  htmlAnalysis: mongoose.Schema.Types.Mixed,
  errorHandling: {
    check404: mongoose.Schema.Types.Mixed,
  },
  metrics: {
    vulnCount: Number,
    missingSecHeaders: Number,
    weakCookies: Number,
    cspIssues: Number,
  },

  // ==================== NEW FEATURES (✅ ADD THESE) ====================

  // 🆕 Firewall/WAF Detection
  firewall: {
    detected: { type: Boolean, default: false },
    wafType: String,
    confidence: String,
    details: [String],
    fingerprints: [mongoose.Schema.Types.Mixed],
    testResults: [mongoose.Schema.Types.Mixed],
    error: String,
  },

  // 🆕 Session Management
  sessionManagement: {
    sessionCreated: { type: Boolean, default: false },
    sessionCookies: [mongoose.Schema.Types.Mixed],
    securityIssues: [mongoose.Schema.Types.Mixed],
    sessionDetails: mongoose.Schema.Types.Mixed,
    error: String,
  },

  // 🆕 Port Scanning
  portScan: {
    scanned: { type: Boolean, default: false },
    scanType: String,
    hostStatus: String,
    openPorts: [mongoose.Schema.Types.Mixed],
    closedPorts: [mongoose.Schema.Types.Mixed],
    filteredPorts: [mongoose.Schema.Types.Mixed],
    totalScanned: Number,
    scanDuration: Number,
    securityImpact: [mongoose.Schema.Types.Mixed],
  },

  // 🆕 Service Detection (Extended)
  serviceDetection: {
    serverInfo: mongoose.Schema.Types.Mixed,
    frameworks: [mongoose.Schema.Types.Mixed],
    technologies: [mongoose.Schema.Types.Mixed],
    cms: mongoose.Schema.Types.Mixed,
    applicationServers: [mongoose.Schema.Types.Mixed],
    databases: [mongoose.Schema.Types.Mixed],
    deviceType: String,
    httpInfo: mongoose.Schema.Types.Mixed,
    cpe: [mongoose.Schema.Types.Mixed],
    cgiTesting: mongoose.Schema.Types.Mixed,
    postgresqlDetection: mongoose.Schema.Types.Mixed,
    traceroute: mongoose.Schema.Types.Mixed,
    networkTimings: mongoose.Schema.Types.Mixed,
    fqdnInfo: mongoose.Schema.Types.Mixed,
    externalUrls: [String],
  },

  // 🆕 Web Mirroring/Crawler
  webMirror: {
    startUrl: String,
    totalPages: Number,
    totalDiscovered: Number,
    maxDepthReached: Number,
    pages: [mongoose.Schema.Types.Mixed],
    assets: mongoose.Schema.Types.Mixed,
    errors: [mongoose.Schema.Types.Mixed],
    crawlTime: String,
    crawlDuration: Number,
    error: String,
  },

  // 🆕 Directory/File Enumeration (Gobuster)
  directoryEnumeration: {
    tested: { type: Boolean, default: false },
    totalTested: Number,
    foundPaths: [mongoose.Schema.Types.Mixed],
    errors: [String],
    scanDuration: Number,
    error: String,
  },

}, {
  strict: false,  // ✅ Allow flexible nested fields
  minimize: false, // ✅ Keep empty objects/arrays
  timestamps: true, // ✅ Auto-add createdAt and updatedAt
});

// ==================== INDEXES FOR PERFORMANCE ====================
scanResultSchema.index({ domain: 1, timestamp: -1 });
scanResultSchema.index({ scanId: 1 });
scanResultSchema.index({ 'firewall.detected': 1 });
scanResultSchema.index({ 'portScan.scanned': 1 });
scanResultSchema.index({ 'directoryEnumeration.tested': 1 });

// ==================== PRE-SAVE HOOK ====================
scanResultSchema.pre('save', function (next) {
  // Convert headers object to plain object if it exists
  if (this.headers && typeof this.headers === 'object') {
    this.headers = JSON.parse(JSON.stringify(this.headers));
  }

  // Ensure vulnerability breakdown is calculated
  if (!this.vulnerabilityBreakdown && this.vulnerabilities) {
    const breakdown = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    this.vulnerabilities.forEach(v => {
      const severity = v.severity?.toLowerCase();
      if (breakdown[severity] !== undefined) {
        breakdown[severity]++;
      }
    });

    this.vulnerabilityBreakdown = breakdown;
  }

  next();
});

// ==================== INSTANCE METHODS ====================
scanResultSchema.methods.getSummary = function () {
  return {
    domain: this.domain,
    timestamp: this.timestamp,
    riskLevel: this.riskLevel,
    vulnerabilityCount: this.vulnerabilityCount,
    securityGrade: this.securityGrade,
    sslValid: this.ssl?.valid,
    firewallDetected: this.firewall?.detected,
    portScanCompleted: this.portScan?.scanned,
    directoryEnumCompleted: this.directoryEnumeration?.tested,
  };
};

// ==================== STATIC METHODS ====================
scanResultSchema.statics.getRecentScans = function (domain, limit = 10) {
  return this.find({ domain })
    .select('domain timestamp vulnerabilityCount riskLevel securityGrade ssl.valid')
    .sort({ timestamp: -1 })
    .limit(limit);
};

scanResultSchema.statics.getDomainStats = async function (domain) {
  const scans = await this.find({ domain }).sort({ timestamp: -1 });

  if (scans.length === 0) return null;

  return {
    totalScans: scans.length,
    latestScan: scans[0],
    averageVulnerabilities: scans.reduce((sum, s) => sum + (s.vulnerabilityCount || 0), 0) / scans.length,
    riskLevelHistory: scans.map(s => ({ timestamp: s.timestamp, riskLevel: s.riskLevel })),
    firewallDetectionRate: scans.filter(s => s.firewall?.detected).length / scans.length,
  };
};

export default mongoose.models.ScanResult || mongoose.model('ScanResult', scanResultSchema);
