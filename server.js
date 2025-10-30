import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import connectDB from './utils/db.js';
import { authMiddleware } from './middleware/authMiddleware.js';
import { checkCredits } from './middleware/checkCredits.js';

// Import routers
import userRoutes from './routers/userRoutes.js'; // Added
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
// import oauthTokenRoutes from './routers/oauth.router.js';
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
import secureCryptRoutes from './routers/secureCryptRouter.js';
import nexposeRoutes from './routers/nexposeRouter.js';
import mdrMonitorRouter from './routers/mdrMonitorRouter.js';
import fileScannerRoutes from './routers/fileScannerRouter.js';
import scanUSBRoutes from './routers/usbScannerRoutes.js';
import dataLeakRoutes from './routers/dataLeakRoutes.js';
import socialPrivacyRoutes from './routers/socialPrivacyRoutes.js';
import fakeSoftwareRoutes from './routers/fakeSoftwareRouter.js';
import whatsappPrivacyRoutes from './routers/whatsappPrivacyRouter.js';
import emailAttachmentRoutes from './routers/emailAttachmentRouter.js';
import ipInfoRoutes from './routers/ipInfoRouter.js';
import thirdPartyPermissionRoutes from './routers/thirdPartyPermissionRouter.js';
import portActivityRouter from './routers/portActivityRouter.js';
import qrRoutes from './routers/qrRoute.js';
import seoRoutes from './routers/seoRouter.js';
import sqliRoutes from './routers/sqliRouter.js';
import contactRoutes from './routers/contactRoutes.js';
import urlShortenerRoutes from './routers/urlShortenerRouter.js';
import osintRouter from './routers/osintRouter.js';
import dbScanRouter from './routers/dbScanRouter.js';
import keywordRouter from './routers/keywordRouter.js';
import bruteForceRoutes from './routers/bruteForceRouter.js';

import sourceCodeRoutes from "./routers/sourceCodeRoutes.js";
// import handler from './routers/image-proxy.js';
import passwordStrength from './routers/passwordStrengthRoutes.js';

import domainToIp from './routers/domainToIp.js';

import feedback from './routers/feedbackRouter.js'
// import wiresharkRoutes from './routers/wireSharkRoutes.js';

import schedulemetting from './routers/schedulemeetingRoutes.js';

import blogs from './routers/blogs.router.js';



const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cookieParser());
app.use(cors({
  origin: ['http://localhost:3000', 'https://your-frontend.example'],
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use((req, res, next) => {
  console.log(`[${req.method}] ${req.url}`);
  next();
});

// Security headers
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      fontSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "blob:"],
      connectSrc: ["'self'", 'http://localhost:4180', 'https://zypher-api.code4bharat.com'],
      objectSrc: ["'none'"]
    }
  })
);

// MongoDB
await connectDB();

// Global Login + Credits
const TOOL_COST = 1;
const toolRoutes = [
  '/api/waf', '/api/sharepoint', '/api/wordpress',
  '/api/sitemap', '/api/keyword', '/api/speed', '/api/meta',
  '/api/jwtsign', '/api/clickjacking', '/api/http', '/api/port-scanner', '/api/asnLookup',
  '/api/mocha', '/api/reverse', '/api/csrf', '/api/regex', '/api/session',
  '/api/whois', '/api/xssTester', '/api/secretKeyScanner', '/api/openRedirectTester',
  '/api/code', '/api/analysis', '/api/sonar', '/api/analyze', '/api/apiTest',
  '/api/fingerprint', '/api/brokenAccess', '/api/ssrf', '/api/sensitiveFile', '/api/link-detector',
  '/api/securecrypt', '/api/nexpose', '/api/mdr-monitor', '/api/file', '/api/scan-usb',
  '/api/data-leak', '/api/socialPrivacy', '/api/fakeSoftware', '/api/whatsapp-privacy-inspector',
  '/api/email-attachment', '/api/ipinfo', '/api/permissions', '/api/port-activity', '/api/qr',
  '/api/seo', '/api/osint', '/api/dbscan', '/api/keywords', '/api/bruteForce',
  '/api/domain'
];

// Apply login & credits check to all tool routes
app.use(toolRoutes, authMiddleware, checkCredits(TOOL_COST));

// API Routes
app.use('/api/auth', userRoutes); // Added
app.use('/api/keyword', keywordRoutes);
app.use('/api/speed', speedRoutes);
app.use('/api/meta', metaAnalyzeRoutes);
app.use('/api/blogs', blogs);
// app.use('/api/auth', oauthTokenRoutes); // Note: Potential conflict, see below
app.use('/api/jwtsign', jwtsignatureRoutes);
app.use('/api/clickjacking', clickjackingRouter);
app.use('/api/http', httpsRouter);
app.use('/api/port-scanner', portScannerRouter);
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
app.use('/api/securecrypt', secureCryptRoutes);
app.use('/api/nexpose', nexposeRoutes);
app.use('/api/mdr-monitor', mdrMonitorRouter);
app.use('/api/file', fileScannerRoutes);
app.use('/api/scan-usb', scanUSBRoutes);
app.use('/api/data-leak', dataLeakRoutes);
app.use('/api/socialPrivacy', socialPrivacyRoutes);
app.use('/api/fakeSoftware', fakeSoftwareRoutes);
app.use('/api/whatsapp-privacy-inspector', whatsappPrivacyRoutes);
app.use('/api/email-attachment', emailAttachmentRoutes);
app.use('/api/ipinfo', ipInfoRoutes);
app.use('/api/permissions', thirdPartyPermissionRoutes);
app.use('/api/port-activity', portActivityRouter);
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
app.use('/api/domain', domainToIp);

app.use('/api/domain', domainToIp);

app.use('/api/feedback', feedback);

app.use('/api/schedulemeeting', schedulemetting);

app.get('/', (req, res) => {
  res.status(200).send("API is running...");
});

// Start Server
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});