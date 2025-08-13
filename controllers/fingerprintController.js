// controllers/fingerprint.controller.js
import axios from 'axios';
import { FingerprintResult } from '../models/fingerprintModel.js';

const normalizeUrl = (url) => {
  const u = url.trim();
  if (!u) return null;
  return /^https?:\/\//i.test(u) ? u : `https://${u}`;
};

// simple helpers
const has = (headers, key) => Object.prototype.hasOwnProperty.call(headers, key);
const inHtml = (html, rx) => rx.test(html);

export const analyzeFingerprint = async (req, res) => {
  const { url } = req.body || {};
  const fullUrl = normalizeUrl(url);
  if (!fullUrl) return res.status(400).json({ error: 'URL is required' });

  const startedAt = new Date();

  try {
    const response = await axios.get(fullUrl, {
      headers: {
        'User-Agent':
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      },
      timeout: 15000,
      maxRedirects: 5,
      validateStatus: () => true, // we still want HTML even for 4xx/5xx
    });

    const finishedAt = new Date();
    const durationMs = finishedAt - startedAt;

    const html = String(response.data || '');
    const headers = response.headers || {};
    const technologies = [];

    // --- Header-based signals ---
    if (has(headers, 'x-powered-by')) technologies.push(`🧠 X-Powered-By: ${headers['x-powered-by']}`);
    if (has(headers, 'server'))       technologies.push(`🖥️ Server: ${headers['server']}`);
    if (has(headers, 'x-vercel-id'))  technologies.push('🚀 Hosting: Vercel');
    if (has(headers, 'cf-ray'))       technologies.push('☁️ CDN: Cloudflare');
    if (has(headers, 'x-nf-request-id')) technologies.push('🚀 Hosting: Netlify');
    if (has(headers, 'x-shopify-stage') || has(headers, 'x-shopid')) technologies.push('🏪 Website Builder: Shopify');
    if (has(headers, 'x-sqsp-cache') || has(headers, 'x-squarespace-cache')) technologies.push('🏗️ Website Builder: Squarespace');

    // --- HTML-based signals (CMS / JS / CSS / Builders / Analytics) ---
    // CMS
    if (/generator"[^>]*content="[^"]*wordpress/i.test(html) || /wp-content\//i.test(html))
      technologies.push('📝 CMS: WordPress');
    if (/generator"[^>]*content="[^"]*joomla/i.test(html))
      technologies.push('🧱 CMS: Joomla');
    if (/generator"[^>]*content="[^"]*drupal/i.test(html) || /sites\/default\/files/i.test(html))
      technologies.push('🌐 CMS: Drupal');
    if (/generator"[^>]*content="[^"]*ghost/i.test(html))
      technologies.push('👻 CMS: Ghost');
    if (/generator"[^>]*content="[^"]*blogger/i.test(html))
      technologies.push('📰 CMS: Blogger');
    if (/magento/i.test(html) || /mage\.cookies/i.test(html))
      technologies.push('🛒 CMS: Magento');
    if (/opencart/i.test(html))
      technologies.push('🛒 CMS: OpenCart');

    // Website builders
    if (/wix\.com|wixstatic\.com|X-Wix-Request-Id/i.test(html) || has(headers, 'x-wix-request-id'))
      technologies.push('🏗️ Website Builder: Wix');
    if (/webflow\.io|data-wf-site/i.test(html))
      technologies.push('🏗️ Website Builder: Webflow');
    // Shopify (additional html cues)
    if (/cdn\.shopify\.com|Shopify\.theme/i.test(html))
      technologies.push('🏪 Website Builder: Shopify');
    // Squarespace (additional html cues)
    if (/squarespace\.com|static1\.squarespace\.com/i.test(html))
      technologies.push('🏗️ Website Builder: Squarespace');

    // JavaScript frameworks
    if (/react|__REACT_DEVTOOLS_GLOBAL_HOOK__/i.test(html)) technologies.push('⚛️ JavaScript: React');
    if (/__VUE_DEVTOOLS_GLOBAL_HOOK__/i.test(html) || /vue(?:\.[\w-]+)?\.js/i.test(html)) technologies.push('🖖 JavaScript: Vue.js');
    if (/ng-version|angular(?:\.[\w-]+)?\.js/i.test(html)) technologies.push('📐 JavaScript: Angular');
    if (/jquery(?:\.[\w-]+)?\.js/i.test(html) || /jQuery/i.test(html)) technologies.push('💡 JavaScript Library: jQuery');

    // CSS frameworks
    if (/bootstrap(?:\.[\w-]+)?\.css/i.test(html)) technologies.push('🎨 CSS Framework: Bootstrap');
    if (/tailwind(?:\.[\w-]+)?\.css|data-tailwind/i.test(html)) technologies.push('🌬️ CSS Framework: Tailwind CSS');

    // Analytics / Tag managers
    if (/www\.googletagmanager\.com\/gtm\.js|GTM-[A-Z0-9]+/i.test(html))
      technologies.push('📦 Tag Manager: Google Tag Manager');
    if (/gtag\('config'|www\.googletagmanager\.com\/gtag\/js\?id=G-/i.test(html))
      technologies.push('📊 Analytics: Google Analytics 4 (gtag.js)');
    if (/analytics\.js|ga\('create'|ga\('send'/i.test(html))
      technologies.push('📊 Analytics: Google Analytics (Universal)');
    if (/connect\.facebook\.net\/.*fbevents\.js|fbq\('init'/i.test(html))
      technologies.push('📈 Analytics: Facebook Pixel');
    if (/static\.hotjar\.com|hotjar\.js|hj\('/i.test(html))
      technologies.push('🔥 Analytics: Hotjar');
    if (/cdn\.mxpnl\.com\/libs\/mixpanel|mixpanel\./i.test(html))
      technologies.push('📈 Analytics: Mixpanel');
    if (/matomo\.js|\/piwik\.php/i.test(html))
      technologies.push('📈 Analytics: Matomo (Piwik)');
    if (/snap\.licdn\.com\/li\.lms-analytics\/insight\.min\.js/i.test(html))
      technologies.push('🔗 Analytics: LinkedIn Insight');

    // Payments / commerce
    if (/checkout\.stripe\.com|js\.stripe\.com/i.test(html)) technologies.push('💳 Payment: Stripe');
    if (/paypalobjects\.com|www\.paypal\.com\/sdk\/js/i.test(html)) technologies.push('💳 Payment: PayPal');
    if (/razorpay\.com\/v1\/checkout\.js/i.test(html)) technologies.push('💳 Payment: Razorpay');

    // Fallback
    if (technologies.length === 0) technologies.push('No identifiable tech found');

    // Persist only basic result (keep your model simple)
    const saved = await FingerprintResult.create({
      url: fullUrl,
      technologies,
      timestamp: new Date(),
    });

    return res.status(200).json({
      technologies: saved.technologies,
      timestamp: saved.timestamp,
      // 👇 extra metadata for UI (not persisted, by your choice)
      meta: {
        startedAt,
        finishedAt,
        durationMs,
        status: response.status,
        finalUrl: response.request?.res?.responseUrl || fullUrl, // axios node adapter
        contentLength: headers['content-length'] ? Number(headers['content-length']) : undefined,
      },
    });
  } catch (err) {
    const finishedAt = new Date();
    const durationMs = finishedAt - startedAt;

    console.error('Fingerprint error:', err.message);
    return res.status(500).json({
      error: 'Failed to fingerprint technologies',
      meta: { startedAt, finishedAt, durationMs },
    });
  }
};
