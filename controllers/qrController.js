import QRCode from 'qrcode';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const Jimp = require('jimp');
const jsQR = require('jsqr');

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ✅ Generate QR Code
export const generateQRController = async (req, res) => {
  try {
    const { text } = req.body;

    if (!text) {
      return res.status(400).json({ status: 'error', message: 'Text is required' });
    }

    const qrImageBuffer = await QRCode.toBuffer(text); // Generates buffer

    res.setHeader('Content-Type', 'image/png');
    res.send(qrImageBuffer);
  } catch (err) {
    console.error('[QR Generate Error]', err);
    res.status(500).json({ status: 'error', message: 'Failed to generate QR code' });
  }
};

// ✅ Scan QR Code
export const scanQRController = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ status: 'error', message: 'No file uploaded' });
    }

    const imagePath = path.join(__dirname, '..', 'uploads', req.file.filename);
    const image = await Jimp.read(imagePath);

    const imageBitmap = {
      data: new Uint8ClampedArray(image.bitmap.data),
      width: image.bitmap.width,
      height: image.bitmap.height,
    };

    const qrCode = jsQR(imageBitmap.data, imageBitmap.width, imageBitmap.height);

    fs.unlinkSync(imagePath); // Clean up uploaded image after scan

    if (qrCode) {
      res.status(200).json({ status: 'success', message: qrCode.data });
    } else {
      res.status(400).json({ status: 'error', message: 'QR code not detected' });
    }
  } catch (err) {
    console.error('[QR Scan Error]', err);
    res.status(500).json({ status: 'error', message: 'Failed to scan QR code' });
  }
};
