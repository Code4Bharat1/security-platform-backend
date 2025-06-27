// server.js (already using ES Modules)
import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import cors from 'cors';
import connectDB from './utils/db.js';

// Importing all routers
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
import jwtRoutes from './routers/jwtRoutes.js';
import jwtsignatureRoutes from './routers/jwtsignature.routes.js';
import IPGeoRouter from './routers/ipgeo.router.js';
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
import bruteForceRoutes from './routers/bruteForceRouter.js';
import brokenAccessRoutes from './routers/brokenAccessRouter.js';
import ssrfRoutes from './routers/ssrfRouter.js';
import sensitiveFileRoutes from './routers/sensitiveFileRouter.js';
import aiRoutes from './routers/aiRouter.js';
import aiHeaderRoutes from './routers/aiHeaderRouter.js';

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use((req, res, next) => {
  console.log(`[${req.method}] ${req.url}`);
  next();
});

// Mount all routes
app.use('/api/keyword', keywordRoutes);
app.use('/api/speed', speedRoutes);
app.use('/api/meta', metaAnalyzeRoutes);
app.use('/api/auth', oauthTokenRoutes);
app.use('/api/jwt', jwtRoutes);
app.use('/api/jwtsign', jwtsignatureRoutes);
app.use('/api/ipgeo', IPGeoRouter);
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
app.use('/api/bruteForce', bruteForceRoutes);

// Start server after DB connected
connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
  });

});
