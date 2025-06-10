import { OpenRedirect } from '../models/openRedirectModel.js';
import axios from 'axios';
import { URL } from 'url';

export const testOpenRedirect = async (req, res) => {
  const { url, paramName } = req.body;
    
  if (!url || !paramName) {
    return res.status(400).json({ error: 'URL and parameter name are required.' });
  }

  try {
    const originalUrl = new URL(url);
    const originalDomain = originalUrl.hostname;

    // Replace the redirect target with a test domain
    originalUrl.searchParams.set(paramName, 'https://evil.com');
    const testedUrl = originalUrl.toString();

    // Make request and follow redirects
    const response = await axios.get(testedUrl, {
      maxRedirects: 10,
      timeout: 10000,
      validateStatus: (status) => status >= 200 && status < 400,
    });

    const finalUrl = response.request?.res?.responseUrl || testedUrl;
    const finalDomain = new URL(finalUrl).hostname;

    const vulnerable = finalDomain !== originalDomain;

    const record = await OpenRedirect.create({
      originalUrl: url,
      testedUrl,
      finalUrl,
      originalDomain,
      finalDomain,
      vulnerable,
    });

    return res.json(record);
  } catch (error) {
    console.error('Open Redirect Test Error:', error.message);
    return res.status(500).json({ error: 'Failed to test URL', details: error.message });
  }
};
