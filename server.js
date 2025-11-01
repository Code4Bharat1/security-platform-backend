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
import userRoutes from './routers/userRoutes.js';
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
import passwordStrength from './routers/passwordStrengthRoutes.js';
import domainToIp from './routers/domainToIp.js';
import feedback from './routers/feedbackRouter.js';
import schedulemetting from './routers/schedulemeetingRoutes.js';
import blogs from './routers/blogs.router.js';

const app = express();
const PORT = process.env.PORT || 5000;

// ==================== MIDDLEWARE CONFIGURATION ====================
// ⚠️ ORDER IS CRITICAL - DO NOT CHANGE

// 1. Cookie Parser (FIRST)
app.use(cookieParser());

// 2. CORS Configuration (BEFORE Helmet and Body Parsers)
const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:5173',
  'https://security-platform.code4bharat.com'
];

const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, Postman, curl, etc.)
    if (!origin) return callback(null, true);

    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.warn(`❌ CORS blocked origin: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Requested-With',
    'Accept',
    'Origin',
    'Cookie'
  ],
  exposedHeaders: ['Set-Cookie'],
  maxAge: 86400, // 24 hours
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));

// Handle preflight requests explicitly
// ✅ Use this instead
app.use((req, res, next) => {
  if (req.method === 'OPTIONS') {
    res.header('Access-Control-Allow-Origin', req.headers.origin);
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin, Cookie');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Max-Age', '86400');
    return res.sendStatus(200);
  }
  next();
});


// 3. Body Parsers
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// 4. Request Logger
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] [${req.method}] ${req.url} - Origin: ${req.headers.origin || 'No origin'}`);
  next();
});

// 5. Helmet Security Headers (AFTER CORS)
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          "'unsafe-inline'",
          "'unsafe-eval'",
          "https://cdn.tailwindcss.com",
          "https://unpkg.com"
        ],
        styleSrc: [
          "'self'",
          "'unsafe-inline'",
          "https://fonts.googleapis.com",
          "https://cdn.tailwindcss.com"
        ],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:", "blob:", "https:"],
        connectSrc: [
          "'self'",
          "http://localhost:*",
          "http://127.0.0.1:*",
          "https://security-platform-api.code4bharat.com",
          "wss://security-platform-api.code4bharat.com",
          "https://zypher-api.code4bharat.com"
        ],
        frameSrc: ["'self'"],
        frameAncestors: ["'none'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"]
      }
    },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" },
    crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" }
  })
);

// 6. Additional CORS Headers (for maximum compatibility)
app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin, Cookie');
    res.setHeader('Access-Control-Expose-Headers', 'Set-Cookie');
  }

  // Handle preflight
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Max-Age', '86400');
    return res.status(200).end();
  }

  next();
});

// 7. Static file serving
app.use('/uploads', express.static('uploads'));

// ==================== DATABASE CONNECTION ====================
await connectDB();

// ==================== AUTHENTICATION & CREDITS ====================
const TOOL_COST = 1;
const toolRoutes = [
  '/api/waf',
  '/api/sharepoint',
  '/api/wordpress',
  '/api/sitemap',
  '/api/keyword',
  '/api/speed',
  '/api/meta',
  '/api/jwtsign',
  '/api/clickjacking',
  '/api/http',
  '/api/port-scanner',
  '/api/asnLookup',
  '/api/mocha',
  '/api/reverse',
  '/api/csrf',
  '/api/regex',
  '/api/session',
  '/api/whois',
  '/api/xssTester',
  '/api/secretKeyScanner',
  '/api/openRedirectTester',
  '/api/code',
  '/api/analysis',
  '/api/sonar',
  '/api/analyze',
  '/api/apiTest',
  '/api/fingerprint',
  '/api/brokenAccess',
  '/api/ssrf',
  '/api/sensitiveFile',
  '/api/link-detector',
  '/api/securecrypt',
  '/api/nexpose',
  '/api/mdr-monitor',
  '/api/file',
  '/api/scan-usb',
  '/api/data-leak',
  '/api/socialPrivacy',
  '/api/fakeSoftware',
  '/api/whatsapp-privacy-inspector',
  '/api/email-attachment',
  '/api/ipinfo',
  '/api/permissions',
  '/api/port-activity',
  '/api/qr',
  '/api/seo',
  '/api/osint',
  '/api/dbscan',
  '/api/keywords',
  '/api/bruteForce',
  '/api/domain'
];

// Apply authentication & credits check to protected routes
app.use(toolRoutes, authMiddleware, checkCredits(TOOL_COST));

// ==================== API ROUTES ====================
// Authentication (Public - no auth required)
app.use('/api/auth', userRoutes);

// Blogs (Public)
app.use('/api/blogs', blogs);

// Contact (Public)
app.use('/api/contact', contactRoutes);

// Feedback (Public)
app.use('/api/feedback', feedback);

// Schedule Meeting (Public)
app.use('/api/schedulemeeting', schedulemetting);

// URL Shortener (Public)
app.use('/', urlShortenerRoutes);

// Protected Routes (Require auth + credits)
app.use('/api/keyword', keywordRoutes);
app.use('/api/speed', speedRoutes);
app.use('/api/meta', metaAnalyzeRoutes);
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
app.use('/api/seo', seoRoutes);
app.use('/api/osint', osintRouter);
app.use('/api/dbscan', dbScanRouter);
app.use('/api/keywords', keywordRouter);
app.use('/api/bruteForce', bruteForceRoutes);
app.use('/api/password', passwordStrength);
app.use('/api/domain', domainToIp);

// ==================== HEALTH CHECK ====================
app.get('/', (req, res) => {
  res.status(200).json({
    status: 'success',
    message: 'Security Platform API is running',
    environment: process.env.NODE_ENV || 'development',
    timestamp: new Date().toISOString()
  });
});

// ==================== ERROR HANDLING ====================
// 404 Handler
app.use((req, res) => {
  res.status(404).json({
    status: 'error',
    message: 'Route not found',
    path: req.originalUrl
  });
});

// Global Error Handler
app.use((err, req, res, next) => {
  console.error('❌ Error:', err.stack);

  res.status(err.status || 500).json({
    status: 'error',
    message: err.message || 'Internal Server Error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

// ==================== START SERVER ====================
app.listen(PORT, () => {
  console.log('\n╔══════════════════════════════════════════════════╗');
  console.log('║     🚀 SECURITY PLATFORM API SERVER STARTED     ║');
  console.log('╚══════════════════════════════════════════════════╝\n');
  console.log(`📡 Server URL: http://localhost:${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`✅ CORS Enabled for:`);
  allowedOrigins.forEach(origin => console.log(`   → ${origin}`));
  console.log(`📅 Started at: ${new Date().toLocaleString()}\n`);
  console.log('═══════════════════════════════════════════════════\n');
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
  console.error('❌ UNHANDLED REJECTION! Shutting down...');
  console.error(err);
  process.exit(1);
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  console.error('❌ UNCAUGHT EXCEPTION! Shutting down...');
  console.error(err);
  process.exit(1);
});
