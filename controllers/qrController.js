import { execFile } from 'child_process';
import fs from 'fs';
import path from 'path'
import { QrResult } from '../models/QrResult.js';

// TODO: Add Download and Copy button once QR Code is generated
// TODO: Add Copy (for all) and (only for link)ablity to click and load the scaned link (if found) in other tab.

export const scanQRCode = async (req, res) => {
  try {
    const imagePath = path.resolve(req.file.path);
    console.log(imagePath)

    execFile('python', ['./scripts/qr_detector.py', imagePath], { encoding: 'utf8' }, (error, stdout, stderr) => {
      if (error) {
      console.log('Script error:', error);

        return res.status(400).json({ status: 'error', message: error });
      }

      if (stderr) {
        console.log('Script error:', stderr);

        return res.status(400).json({ status: 'error', message: stderr });
      }
      fs.unlinkSync(imagePath); // Delete uploaded file

      console.log('Script output:', stdout);
      const qrData = stdout;

      const suspiciousPatterns = ['bit.ly', 'tinyurl', 'gift', 'malware', '.apk', '.exe'];
      const isSuspicious = suspiciousPatterns.some(pattern =>
        qrData.includes(pattern)
      );

      const status = isSuspicious ? 'fake' : 'safe';
      const message = isSuspicious
        ? '⚠️ Fake / suspicious QR code detected!'
        : '✅ Safe QR code. No malicious content found.';

      res.json({ status, data: qrData, message });

    });

  } catch (err) {
    console.error('QR Scan Error:', err);
    res.status(500).json({
      status: 'error',
      message: err.message || 'Server error while scanning QR',
    });
  }
};

export const generateQRCode = (req, res) => {
  try {
    const { text } = req.body; // Expect text to encode in QR code

    if (!text || text.trim() === '') {
      return res.status(400).json({ status: 'error', message: 'No text provided for QR code generation.' });
    }

    // Resolve path to your Python script
    const scriptPath = path.resolve('./scripts/qr_generator.py');

    // Call python script with text argument (make sure to sanitize/escape if needed)
    execFile('python', [scriptPath, text], { encoding: 'utf8' }, (error, stdout, stderr) => {
      if (error) {
        console.error('QR Generator script error:', error);
        return res.status(400).json({ status: 'error', message: error.message });
      }

      if (stderr) {
        console.error('QR Generator stderr:', stderr);
        // optionally still continue or return error
      }

      // stdout could be a path to generated image or base64 string (depends on your python)
      let generatedData = stdout.replaceAll("\r\n", "\n").trim();
      generatedData = generatedData.slice(generatedData.indexOf("\n", 1), generatedData.length)
      console

      // Example: if python returns path to generated QR image
      // You can read the image file and send it back or just return the path or URL.

      // For example, if the python returns a filename, return URL
      // Adjust this based on what your python outputs
      res.json({ status: 'success', data: generatedData, message: 'QR code generated successfully.' });
    });
  } catch (err) {
    console.error('QR Generate Error:', err);
    res.status(500).json({
      status: 'error',
      message: err.message || 'Server error while generating QR code',
    });
  }
};