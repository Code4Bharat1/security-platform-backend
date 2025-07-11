import { BrokenAccessScan } from '../models/brokenAccessModel.js';

export const saveBrokenAccessScan = async (req, res) => {
  const { targetUrl, customPaths = [], authHeader = null } = req.body;
  const results = req.scanResults;

  try {
    const scan = new BrokenAccessScan({
      targetUrl,
      customPaths,
      authHeader,
      results
    });

    await scan.save();

    res.status(200).json({ message: 'Scan completed', results });
  } catch (error) {
    res.status(500).json({ error: 'Failed to save results to database' });
  }
};
