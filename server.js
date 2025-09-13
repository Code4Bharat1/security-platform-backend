// server.js (ES Modules)

import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
// server.js (ES Modules)

import cors from 'cors';

import connectDB from './utils/db.js';

import dnsRoutes from './routers/dnsRouter.js';

import wafRoutes from './routers/wafRouter.js';

import scanRoutes from './routers/scanRouter.js';

import sharePointRoutes from './routers/sharePointRouter.js';

import wordpressRoutes from './routers/wordpressRouter.js';

import sitemapRoutes from './routers/sitemapRouter.js';

import brokenlinkRoutes from './routers/brokenLinkRouter.js';

import keywordRoutes from './routers/keyword.router.js';

import speedRoutes from './routers/speed.router.js';

import metaAnalyzeRoutes from './routers/metaAnalyzeRoutes.js';

import oauthTokenRoutes from './routers/oauth.router.js';

import jwtsignatureRoutes from './routers/jwtsignature.routes.js';

import clickjackingRouter from './routers/clickjacking.router.js';

import httpsRouter from './routers/https.router.js';

import portScannerRouter from './routers/portScanner.router.js';

import asnLookupRouter from './routers/asnlookup.router.js';

import mochaRoutes from './routers/mochaTest.routes.js';

import reverseDNSRoutes from './routers/reverseDNSRoutes.js';

import csrfRoutes from './routers/csrfRoutes.js';

import regexRoutes from './routers/regexRoutes.js';

import sessionFixationRoutes from './routers/sessionFixationRoutes.js';

import whoisRoutes from './routers/whoisRouter.js';

import subdomainRoutes from './routers/subdomainRouter.js';

import xssTesterRoutes from './routers/xssTesterRouter.js';

import secretScanRoutes from './routers/secretScanRouter.js';

import openRedirectRoutes from './routers/openRedirectRouter.js';

import codeObfuscationRoutes from './routers/codeObfuscationRouter.js';

import analysisRoutes from './routers/analysisRouter.js';

import sonarRoutes from './routers/sonarRouter.js';

import analyzeCodeRoutes from './routers/analyzeCodeRouter.js';

import apiTestRoutes from './routers/apiTestRouter.js';

import fingerprintRoutes from './routers/fingerprintRouter.js';

import brokenAccessRoutes from './routers/brokenAccessRouter.js';

import ssrfRoutes from './routers/ssrfRouter.js';

import sensitiveFileRoutes from './routers/sensitiveFileRouter.js';

import linkDetectorRoutes from './routers/linkDetectorRouter.js';

import secureCryptRoutes from "./routers/secureCryptRouter.js";

import nexposeRoutes from './routers/nexposeRouter.js';

import mdrMonitorRouter from "./routers/mdrMonitorRouter.js";

import fileScannerRoutes from "./routers/fileScannerRouter.js";

import scanUSBRoutes from "./routers/usbScannerRoutes.js";

import dataLeakRoutes from './routers/dataLeakRoutes.js';

import socialPrivacyRoutes from "./routers/socialPrivacyRoutes.js";

import fakeSoftwareRoutes from "./routers/fakeSoftwareRouter.js";

import whatsappPrivacyRoutes from './routers/whatsappPrivacyRouter.js';

import emailAttachmentRoutes from "./routers/emailAttachmentRouter.js";

import helmet from 'helmet';

import ipInfoRoutes from "./routers/ipInfoRouter.js";

import thirdPartyPermissionRoutes from "./routers/thirdPartyPermissionRouter.js";

import portActivityRouter from "./routers/portActivityRouter.js";

import qrRoutes from './routers/qrRoute.js';

import seoRoutes from './routers/seoRouter.js';

import sqliRoutes from "./routers/sqliRouter.js";

import contactRoutes from './routers/contactRoutes.js';

import urlShortenerRoutes from './routers/urlShortenerRouter.js';

import osintRouter from './routers/osintRouter.js';

import dbScanRouter from './routers/dbScanRouter.js';

import keywordRouter from './routers/keywordRouter.js';

import bruteForceRoutes from './routers/bruteForceRouter.js';

import sourceCodeRoutes from "./routers/sourceCodeRoutes.js";

import passwordStrength from './routers/passwordStrengthRoutes.js';
import domainToIp from './routers/domainToIp.js';

// import wiresharkRoutes from './routers/wireSharkRoutes.js';


import blogs from './routers/blogs.js';



const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use((req, res, next) => {
  console.log(`[${req.method}] ${req.url}`);
  next();
});

//helmet for security headers
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      fontSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "blob:"],
      connectSrc: [
        "'self'",
        'http://localhost:4180', // 👈 Allow local API
        'https://zypher-api.code4bharat.com' // 👈 If needed
      ],
      objectSrc: ["'none'"]
    }
  })
);
// DB Connection
await connectDB(); // ✅ uses mongoose.connect() inside utils/db.js

// API Routes Mounting

app.use('/api/keyword', keywordRoutes);

app.use('/api/speed', speedRoutes);

app.use('/api/meta', metaAnalyzeRoutes);

app.use('/api/blogs', blogs);

app.use('/api/auth', oauthTokenRoutes);

app.use('/api/jwtsign', jwtsignatureRoutes);

app.use('/api/clickjacking', clickjackingRouter);

app.use('/api/http', httpsRouter);

app.use('/api/port', portScannerRouter);

app.use('/api/asnLookup', asnLookupRouter);

app.use('/api/mocha', mochaRoutes);

app.use('/api/reverse', reverseDNSRoutes);

app.use('/api/csrf', csrfRoutes);

app.use('/api/regex', regexRoutes);

app.use('/api/session', sessionFixationRoutes);

app.use('/api/dns', dnsRoutes);

app.use('/api/waf', wafRoutes);

app.use('/api/scan', scanRoutes);

app.use('/api/sharepoint', sharePointRoutes);

app.use('/api/wordpress', wordpressRoutes);

app.use('/api/sitemap', sitemapRoutes);

app.use('/api/brokenlink', brokenlinkRoutes);

app.use('/api/whois', whoisRoutes);

app.use('/api/subdomain', subdomainRoutes);

app.use('/api/xssTester', xssTesterRoutes);

app.use('/api/secretKeyScanner', secretScanRoutes);

app.use('/api/openRedirectTester', openRedirectRoutes);

app.use('/api/code', codeObfuscationRoutes);

app.use('/api/analysis', analysisRoutes);

app.use('/api/sonar', sonarRoutes);

app.use('/api/analyze', analyzeCodeRoutes);

app.use('/api/apiTest', apiTestRoutes);

app.use('/api/fingerprint', fingerprintRoutes);

app.use('/api/brokenAccess', brokenAccessRoutes);

app.use('/api/ssrf', ssrfRoutes);

app.use('/api/sensitiveFile', sensitiveFileRoutes);

app.use('/api/link-detector', linkDetectorRoutes);

app.use("/api/securecrypt", secureCryptRoutes);

app.use('/api/nexpose', nexposeRoutes);

app.use("/api/mdr-monitor", mdrMonitorRouter);

app.use("/api/file", fileScannerRoutes);

app.use("/api/scan-usb", scanUSBRoutes);

app.use("/api/data-leak", dataLeakRoutes);

app.use("/api", socialPrivacyRoutes);

app.use("/api", fakeSoftwareRoutes);

app.use("/api/whatsapp-privacy-inspector", whatsappPrivacyRoutes);

app.use("/api/email-attachment", emailAttachmentRoutes);

app.use("/api/ipinfo", ipInfoRoutes);

app.use("/api/permissons", thirdPartyPermissionRoutes);

app.use("/api/port", portActivityRouter);

app.use('/api/qr', qrRoutes);

app.use('/uploads', express.static('uploads'));

app.use('/api/seo', seoRoutes);

app.use('/api/contact', contactRoutes);

app.use('/', urlShortenerRoutes);

app.use('/api/osint', osintRouter);

app.use('/api/dbscan', dbScanRouter);

app.use('/api/keywords', keywordRouter);

app.use('/api/bruteForce', bruteForceRoutes);

app.use('/api/password', passwordStrength);

app.use('/api/domain',domainToIp);

// app.use('/api/wire',wiresharkRoutes);

app.get('/', (req, res) => {
  res.status(200).send("API is running...")
})

// Start Server
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
