import { BrokenAccessScan } from '../models/brokenAccessModel.js';

export const getBrokenAccessReports = async (req, res) => {
  try {
    const scans = await BrokenAccessScan.find().sort({ createdAt: -1 }).limit(20); // latest 20
    res.json({ reports: scans });
  } catch (err) {
    console.error('Error fetching reports:', err);
    res.status(500).json({ error: 'Failed to fetch reports' });
  }
};
