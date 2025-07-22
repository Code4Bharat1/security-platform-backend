import fs from 'fs';
import QrCode from 'qrcode-reader';
import { QrResult } from '../models/QrResult.js';
import { Jimp } from 'jimp';
import path from 'path';

export const scanQRCode = async (req, res) => {
  try {
    const imagePath = req.file.path;
    const fullPath = path.join(imagePath);
    const buffer = fs.readFileSync(fullPath);

    const qrData = await Promise.race([
      new Promise(async (resolve) => {
        const imgData = await Jimp.read(buffer)
        const qr = new QrCode();
        qr.callback = function (error, result) {
          if (error || !result) {
            console.log(error)
            return resolve({error: 1, message: error});
          }
          console.log(result)
          resolve({error: 0, message: error});
        }
        qr.decode(imgData.bitmap);
      }),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('QR scan timeout')), 5000)
      )
    ]);
    console.log("Hll")
    fs.unlinkSync(imagePath);

    if (qrData.error) {
      return res.status(400).json({ status: 'error', message: qrData.error });
    }

    const suspiciousPatterns = ['bit.ly', 'tinyurl', 'gift', 'malware', '.apk', '.exe'];
    const isSuspicious = suspiciousPatterns.some(pattern =>
      qrData.result.includes(pattern)
    );

    const status = isSuspicious ? 'fake' : 'safe';
    const message = isSuspicious
      ? '⚠️ Fake / suspicious QR code detected!'
      : '✅ Safe QR code. No malicious content found.';

    await new QrResult({ data: JSON.stringify(qrData), status, reason: message }).save();

    res.json({ status, data: qrData, message });

  } catch (err) {
    console.error('QR Scan Error:', err);
    res.status(500).json({ status: 'error', message: err.message || 'Server error while scanning QR' });
  }
};
