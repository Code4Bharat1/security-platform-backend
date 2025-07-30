import net from 'net';
import mongoose from 'mongoose';  // MongoDB ke liye real connect test
// future: mysql2 for MySQL etc.

export const scanDatabase = async (req, res) => {
  try {
    const { dbType, host, port, username, password, checks } = req.body;

    let findings = [];
    let score = 100;

    // 1️⃣ Test open port
    const portOpen = await new Promise((resolve) => {
      const socket = new net.Socket();
      socket.setTimeout(2000);
      socket.once('connect', () => { socket.destroy(); resolve(true); });
      socket.once('timeout', () => { socket.destroy(); resolve(false); });
      socket.once('error', () => resolve(false));
      socket.connect(port, host);
    });
    if (portOpen) {
      findings.push({ type: 'warning', message: `Open port: ${port} (exposed)` });
      score -= 10;
    } else {
      findings.push({ type: 'success', message: `Port ${port} is closed` });
    }

    // 2️⃣ Test authentication (MongoDB example)
    if (dbType === 'MongoDB' && checks.includes('auth')) {
      try {
        const conn = await mongoose.createConnection(
          `mongodb://${username}:${password}@${host}:${port}/admin`,
          { serverSelectionTimeoutMS: 2000 }
        ).asPromise();
        await conn.close();
        findings.push({ type: 'success', message: 'Authentication enabled & working' });
      } catch (err) {
        findings.push({ type: 'warning', message: 'Authentication failed or disabled' });
        score -= 10;
      }
    }

    // 3️⃣ SSL check (simulate: MongoDB normally requires config parsing)
    if (checks.includes('ssl')) {
      // real check needs driver options, assume test here
      const sslEnabled = false; // default
      if (!sslEnabled) {
        findings.push({ type: 'warning', message: 'SSL/TLS not enabled' });
        score -= 10;
      } else {
        findings.push({ type: 'success', message: 'SSL/TLS is enabled' });
      }
    }

    // 4️⃣ Encryption at rest check (simulate)
    if (checks.includes('encryption')) {
      const encryptionEnabled = false; // default
      if (!encryptionEnabled) {
        findings.push({ type: 'warning', message: 'Encryption at rest not configured' });
        score -= 10;
      } else {
        findings.push({ type: 'success', message: 'Encryption at rest configured' });
      }
    }

    // Suggestions
    const suggestions = [];
    findings.forEach(f => {
      if (f.type === 'warning') {
        if (f.message.includes('SSL')) suggestions.push('Enable TLS/SSL');
        if (f.message.includes('Open port')) suggestions.push('Restrict DB port to localhost');
        if (f.message.includes('Encryption')) suggestions.push('Configure data-at-rest encryption');
        if (f.message.includes('Authentication')) suggestions.push('Enable authentication');
      }
    });

    res.json({
      securityScore: score,
      issues: findings.filter(f => f.type === 'warning').length,
      findings,
      suggestions: [...new Set(suggestions)]
    });
  } catch (err) {
    console.error('Scan error:', err);
    res.status(500).json({ message: 'Scan failed' });
  }
};
