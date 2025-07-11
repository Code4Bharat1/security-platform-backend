import crypto from 'crypto';

const SECRET_KEY = crypto.randomBytes(32);
const IV = crypto.randomBytes(16);

export const encryptText = (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ error: 'Text is required.' });

  try {
    const cipher = crypto.createCipheriv('aes-256-cbc', SECRET_KEY, IV);
    let encrypted = cipher.update(text, 'utf-8', 'hex');
    encrypted += cipher.final('hex');

    res.json({ encrypted });
  } catch (err) {
    res.status(500).json({ error: 'Encryption failed.' });
  }
};

export const decryptText = (req, res) => {
  const { encryptedText } = req.body;
  if (!encryptedText) return res.status(400).json({ error: 'Encrypted text is required.' });

  try {
    const decipher = crypto.createDecipheriv('aes-256-cbc', SECRET_KEY, IV);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf-8');
    decrypted += decipher.final('utf-8');

    res.json({ decrypted });
  } catch (err) {
    res.status(400).json({ error: 'Invalid encrypted text.' });
  }
};
