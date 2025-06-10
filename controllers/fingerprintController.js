import axios from 'axios';
import { FingerprintResult } from '../models/fingerprintModel.js';

export const analyzeFingerprint = async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });

  try {
    const fullUrl = url.startsWith('http') ? url : `https://${url}`;
    const response = await axios.get(fullUrl, {
      headers: {
        'User-Agent':
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
        Accept: 'text/html',
      },
      timeout: 10000,
    });

    const html = response.data;
    const headers = response.headers;
    const fingerprints = [];

    // Header-based
    if (headers['x-powered-by']) fingerprints.push(`🧠 X-Powered-By: ${headers['x-powered-by']}`);
    if (headers['server']) fingerprints.push(`🖥️ Server: ${headers['server']}`);
    if (headers['x-vercel-id']) fingerprints.push('🚀 Hosting: Vercel');
    if (headers['cf-ray']) fingerprints.push('☁️ CDN: Cloudflare');

    // HTML content-based
    if (/generator.*wordpress/i.test(html)) fingerprints.push('📝 CMS: WordPress');
    if (/generator.*joomla/i.test(html)) fingerprints.push('🧱 CMS: Joomla');
    if (/generator.*drupal/i.test(html)) fingerprints.push('🌐 CMS: Drupal');
    if (/react/i.test(html)) fingerprints.push('⚛️ JavaScript: React');
    if (/__VUE_DEVTOOLS_GLOBAL_HOOK__/i.test(html)) fingerprints.push('🖖 JavaScript: Vue.js');
    if (/ng-version/i.test(html)) fingerprints.push('📐 JavaScript: Angular');
    if (/bootstrap.*\.css/i.test(html)) fingerprints.push('🎨 CSS Framework: Bootstrap');
    if (/tailwind.*\.css/i.test(html)) fingerprints.push('🌬️ CSS Framework: Tailwind CSS');
    if (/jquery/i.test(html)) fingerprints.push('💡 JavaScript Library: jQuery');
    if (/google-analytics/i.test(html)) fingerprints.push('📊 Analytics: Google Analytics');
    if (/checkout\.stripe\.com/i.test(html)) fingerprints.push('💳 Payment: Stripe');

    const tech = fingerprints.length ? fingerprints : ['No identifiable tech found'];

    const result = await FingerprintResult.create({
      url: fullUrl,
      technologies: tech,
      timestamp: new Date(),
    });

    res.json({ technologies: result.technologies, timestamp: result.timestamp });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: 'Failed to fingerprint technologies' });
  }
};
