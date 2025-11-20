// server.js
// Minimal Express server for /roll endpoint + static files
// Optional in-memory store of rolls (STORE_ROLLS=true)
// Admin endpoint to view stored rolls (protected by ADMIN_TOKEN env var)

const express = require('express');
const crypto = require('crypto');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// CORS: allow configurable origin, default allow all
const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN || '*';
app.use(cors({
  origin: ALLOW_ORIGIN,
  optionsSuccessStatus: 204
}));

// Serve static files from ./public (ensure index.html placed there)
app.use(express.static(path.join(__dirname, 'public'), {
  etag: false,
  lastModified: false,
  setHeaders: (res, filePath) => {
    // Make static file responses non-cacheable
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }
}));

// In-memory store (optional)
const STORE_ROLLS = String(process.env.STORE_ROLLS || '').toLowerCase() === 'true';
const rollsStore = {}; // clientId -> array of { number, ts, salt }

function numberFromHash(hashBuf) {
  const v = hashBuf.readUInt32BE(0);
  return (v % 6) + 1;
}

app.get('/roll', (req, res) => {
  // Strict no-cache on the API response
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Surrogate-Control', 'no-store');

  const clientId = String(req.query.client_id || req.headers['x-client-id'] || 'anonymous');
  const ts = Math.floor(Date.now() / 1000);
  const salt = crypto.randomBytes(8).toString('hex');

  const h = crypto.createHash('sha256');
  h.update(clientId);
  h.update(String(ts));
  h.update(salt);
  const digest = h.digest();

  const number = numberFromHash(digest);

  if (STORE_ROLLS) {
    rollsStore[clientId] = rollsStore[clientId] || [];
    rollsStore[clientId].push({ number, ts, salt });
    // avoid unbounded growth in naive in-memory store:
    if (rollsStore[clientId].length > 1000) rollsStore[clientId].shift();
  }

  res.json({
    number,
    info: 'server-roll',
    ts
  });
});

// Simple admin endpoint (protected by ADMIN_TOKEN) to inspect stored rolls
app.get('/admin/rolls', (req, res) => {
  const token = process.env.ADMIN_TOKEN || '';
  const auth = req.headers['x-admin-token'] || req.query.token || '';
  if (!token || auth !== token) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  res.json({ stored: rollsStore });
});

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
