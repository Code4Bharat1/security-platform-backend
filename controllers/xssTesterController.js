// controllers/xssTesterController.js

import { XssTest } from '../models/xssTestModel.js';
import axios from 'axios';

export const testXssPayload = async (req, res) => {
  const { url, param, payload } = req.body;

  if (!url || !param || !payload) {
    return res.status(400).json({ error: 'url, param, and payload are required' });
  }

  try {
    // Build URL with payload injected into query param
    const urlObj = new URL(url);
    urlObj.searchParams.set(param, payload);
    const testUrl = urlObj.toString();
    // Request the URL with payload
      
    const response = await axios.get(testUrl, { timeout: 10000 });

    // You can do some analysis here, for now we just return status and snippet of body
    const isObject = typeof response.data === 'object';
    const snippet = isObject
      ? JSON.stringify(response.data).slice(0, 1000)
      : response.data.slice(0, 1000);
   
    // Save test result to DB
    const savedTest = await XssTest.create({
      url,
      param,
      payload,
      result: {
        status: response.status,
        snippet,
      },
    });

   return res.status(200).json({
      success: true,
      testedUrl: testUrl,
      result: savedTest.result,
    });

  } catch (error) {
    console.error('XSS test error:', error.message);
    return res.status(500).json({ error: 'Failed to perform XSS test', details: error.message });
  }
};
