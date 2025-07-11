import fs from 'fs';
import QrCode from 'qrcode-reader';
import { QrResult } from '../models/QrResult.js';

export const scanQRCode = async (req, res) => {
  try {
    const imagePath = req.file.path;

    // ✅ Proper import
    const Jimp = (await import('jimp')).default;

    const qrData = await Promise.race([
      new Promise((resolve, reject) => {
        Jimp.read(imagePath, (err, image) => {
          if (err) return reject(err);
          const qr = new QrCode();
          qr.callback = (err, value) => {
            if (err || !value) return resolve(null);
            resolve(value.result);
          };
          qr.decode(image.bitmap);
        });
      }),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('QR scan timeout')), 5000)
      )
    ]);

    fs.unlinkSync(imagePath);

    if (!qrData) {
      return res.status(400).json({ status: 'error', message: 'Unable to scan QR code' });
    }

    const suspiciousPatterns = ['bit.ly', 'tinyurl', 'gift', 'malware', '.apk', '.exe'];
    const isSuspicious = suspiciousPatterns.some(pattern =>
      qrData.toLowerCase().includes(pattern)
    );

    const status = isSuspicious ? 'fake' : 'safe';
    const message = isSuspicious
      ? '⚠️ Fake / suspicious QR code detected!'
      : '✅ Safe QR code. No malicious content found.';

    await new QrResult({ data: qrData, status, reason: message }).save();

    res.json({ status, data: qrData, message });

  } catch (err) {
    console.error('QR Scan Error:', err);
    res.status(500).json({ status: 'error', message: err.message || 'Server error while scanning QR' });
  }
};
