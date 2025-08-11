// controllers/clickjacking.controller.js
import ClickjackingTest from '../models/clickjacking.model.js';
import axios from 'axios';
import { URL } from 'url';

export const testClickjacking = async (req, res) => {
  let { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });

  try {
    // Ensure URL starts with http/https
    if (!/^https?:\/\//i.test(url)) {
      url = `https://${url}`;
    }

    // Validate the URL format
    try {
      new URL(url);
    } catch {
      return res.status(400).json({ error: 'Invalid URL format' });
    }

    // Make HEAD request with Axios
    const response = await axios({
      method: 'HEAD',
      url,
      maxRedirects: 5,
      timeout: 8000,
      validateStatus: () => true, // Accept all responses (even 4xx/5xx)
    });

    if (response.status >= 400) {
      return res.status(400).json({
        error: `Could not access site. Status code: ${response.status}`,
      });
    }

    const headers = Object.fromEntries(
      Object.entries(response.headers).map(([key, val]) => [key.toLowerCase(), val])
    );

    const xFrameOptions = headers['x-frame-options'];
    const contentSecurityPolicy = headers['content-security-policy'];

    const protectedBy = [];

    if (xFrameOptions) protectedBy.push(`X-Frame-Options: ${xFrameOptions}`);
    if (contentSecurityPolicy && contentSecurityPolicy.includes('frame-ancestors')) {
      protectedBy.push(`Content-Security-Policy: ${contentSecurityPolicy}`);
    }

    const isProtected = protectedBy.length > 0;

    // Save result in DB
    const testRecord = new ClickjackingTest({
      url,
      isProtected,
      protectedBy,
    });

    await testRecord.save();

    res.status(200).json({
      url,
      isProtected,
      protectedBy,
    });
  } catch (error) {
    console.error('Clickjacking test error:', error.message);
    res.status(500).json({ error: 'Failed to fetch URL or analyze headers' });
  }
};
