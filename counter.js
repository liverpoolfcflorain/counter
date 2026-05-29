const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const axios = require('axios');
const crypto = require('crypto');
require('dotenv').config();

// ─── Optional security packages ───────────────────────────────────────────────
let rateLimit, helmet, slowDown;
try { rateLimit = require('express-rate-limit'); } catch (_) {}
try { helmet   = require('helmet');              } catch (_) {}
try { slowDown = require('express-slow-down');   } catch (_) {}

const app = express();

// ─── trust proxy MUST come first (before rate limiters read req.ip) ───────────
app.set('trust proxy', 1);

// ─── Security headers ─────────────────────────────────────────────────────────
if (helmet) {
  app.use(helmet());
} else {
  console.warn('[WARN] helmet not installed — run: npm install helmet');
}

// ─── CORS ─────────────────────────────────────────────────────────────────────
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || 'https://counter-onlc.onrender.com',
  methods: ['GET', 'POST'],
}));

// ─── Rate limiters ────────────────────────────────────────────────────────────
if (!rateLimit) {
  console.warn('[WARN] express-rate-limit not installed — run: npm install express-rate-limit');
}
if (!slowDown) {
  console.warn('[WARN] express-slow-down not installed — run: npm install express-slow-down');
}

// Global: 200 requests per 15 min per IP
const globalLimiter = rateLimit
  ? rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 200,
      standardHeaders: true,
      legacyHeaders: false,
      message: { status: 'error', message: 'Too many requests. Please try again later.' },
    })
  : (req, res, next) => next();

// Checkout: max 10 attempts per IP per hour
const checkoutLimiter = rateLimit
  ? rateLimit({
      windowMs: 60 * 60 * 1000,
      max: 10,
      keyGenerator: (req) => req.ip,
      message: { status: 'error', message: 'Too many checkout attempts. Please wait before trying again.' },
    })
  : (req, res, next) => next();

// Slow down after 5 checkout attempts in 10 min (express-slow-down v1 API)
const checkoutSlowDown = slowDown
  ? slowDown({
      windowMs: 10 * 60 * 1000,
      delayAfter: 5,
      delayMs: 500,
    })
  : (req, res, next) => next();

app.use(globalLimiter);

// ─── Body parsers ─────────────────────────────────────────────────────────────
// Raw buffer for webhook — Safepay signs raw bytes, not re-serialised JSON.
// MUST be registered before express.json() so the webhook route gets raw body.
app.use('/api/webhooks/safepay', express.raw({ type: 'application/json', limit: '10kb' }));

// JSON parser for all other routes
app.use(express.json({ limit: '10kb' }));

// ─── File paths ───────────────────────────────────────────────────────────────
const PORT         = process.env.PORT || 5000;
const DB_DIR       = path.join(__dirname, 'safepay_db');
const STATS_FILE   = path.join(DB_DIR, 'donation_stats.json');
const DEPOSIT_FILE = path.join(DB_DIR, 'deposits.json');

if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });

if (!fs.existsSync(STATS_FILE)) {
  fs.writeFileSync(STATS_FILE, JSON.stringify({ total: 0, donors: 0 }, null, 2));
}
if (!fs.existsSync(DEPOSIT_FILE)) {
  fs.writeFileSync(DEPOSIT_FILE, JSON.stringify([], null, 2));
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function readJSON(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function writeJSON(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

// ─── POST /api/checkout/safepay ───────────────────────────────────────────────
app.post(
  '/api/checkout/safepay',
  checkoutLimiter,
  checkoutSlowDown,
  async (req, res) => {
    try {
      const { amount } = req.body;
      const numericAmount = parseInt(amount, 10);

      if (isNaN(numericAmount) || numericAmount <= 0 || numericAmount > 10_000_000) {
        return res.status(400).json({ status: 'error', message: 'Invalid donation amount.' });
      }

      const apiKey = process.env.SAFEPAY_SANDBOX_PUBLIC_KEY?.replace(/"/g, '');
      if (!apiKey) {
        return res.status(500).json({ status: 'error', message: 'Payment service not configured.' });
      }

      const response = await axios.post(
        'https://sandbox.api.getsafepay.com/order/v1/init',
        {
          client: apiKey,
          environment: 'sandbox',
          currency: 'PKR',
          amount: numericAmount,
        },
        { headers: { 'Content-Type': 'application/json' }, timeout: 10000 }
      );

      const token = response.data?.data?.token;
      if (!token) throw new Error('No token returned from Safepay.');

      const redirectBase = process.env.REDIRECT_URL || 'https://counter-onlc.onrender.com';
      const checkoutUrl =
        `https://sandbox.api.getsafepay.com/checkout/pay` +
        `?env=sandbox&beacon=${token}&source=custom&webhooks=true` +
        `&redirect_url=${encodeURIComponent(redirectBase)}` +
        `&cancel_url=${encodeURIComponent(redirectBase)}`;

      res.json({ status: 'success', checkoutUrl });
    } catch (error) {
      console.error('[checkout error]', error.response?.data || error.message);
      res.status(500).json({
        status: 'error',
        message: 'Checkout failed.',
      });
    }
  }
);

// ─── POST /api/webhooks/safepay ───────────────────────────────────────────────
// req.body is a raw Buffer here due to express.raw() above — required for valid HMAC.
app.post('/api/webhooks/safepay', (req, res) => {
  const receivedSignature = req.headers['x-safepay-signature'];

  if (!receivedSignature) {
    return res.status(401).json({ status: 'error', message: 'Missing authorization signature.' });
  }

  const webhookSecret = process.env.SAFEPAY_SANDBOX_WEBHOOK_SECRET?.replace(/"/g, '');
  if (!webhookSecret) {
    return res.status(500).json({ status: 'error', message: 'Webhook secret not configured.' });
  }

  const localHash = crypto
    .createHmac('sha256', webhookSecret)
    .update(req.body)
    .digest('hex');

  // Constant-time comparison — wrapped in try/catch for safety
  let signaturesMatch = false;
  try {
    const sigBuf   = Buffer.from(receivedSignature, 'utf8');
    const localBuf = Buffer.from(localHash, 'utf8');
    signaturesMatch =
      sigBuf.length === localBuf.length &&
      crypto.timingSafeEqual(sigBuf, localBuf);
  } catch (e) {
    return res.status(401).json({ status: 'error', message: 'Signature validation failed.' });
  }

  if (!signaturesMatch) {
    return res.status(401).json({ status: 'error', message: 'Signature validation failed.' });
  }

  // Parse raw body now that signature is verified
  let payload;
  try {
    payload = JSON.parse(req.body.toString('utf8'));
  } catch (e) {
    return res.status(400).json({ status: 'error', message: 'Invalid JSON payload.' });
  }

  const { data, event } = payload;

  if (event === 'payment.succeeded') {
    const amount = parseInt(data?.amount, 10);
    if (isNaN(amount) || amount <= 0) {
      return res.status(400).json({ status: 'error', message: 'Invalid amount in payload.' });
    }

    try {
      const stats = readJSON(STATS_FILE);
      stats.total  += amount;
      stats.donors += 1;
      writeJSON(STATS_FILE, stats);

      const MAX_DEPOSITS = 10_000;
      const sanitize = (v, fallback) => {
        if (typeof v !== 'string') return fallback;
        return v.replace(/[^a-zA-Z0-9_\-]/g, '').slice(0, 128) || fallback;
      };

      const deposits = readJSON(DEPOSIT_FILE);
      deposits.push({
        id:        sanitize(data.tracking_id, null) || sanitize(data.token, null) || crypto.randomUUID(),
        amount,
        currency:  sanitize(data.currency, 'PKR'),
        timestamp: new Date().toISOString(),
        event,
      });
      if (deposits.length > MAX_DEPOSITS) deposits.splice(0, deposits.length - MAX_DEPOSITS);
      writeJSON(DEPOSIT_FILE, deposits);

      res.status(200).json({ status: 'success' });
    } catch (err) {
      console.error('[webhook write error]', err.message);
      res.status(500).json({ status: 'error', message: 'Failed to record payment.' });
    }
  } else {
    res.status(200).json({ status: 'event_unhandled' });
  }
});

// ─── GET /api/donations ───────────────────────────────────────────────────────
app.get('/api/donations', (req, res) => {
  try {
    res.status(200).json(readJSON(STATS_FILE));
  } catch (e) {
    res.status(500).json({ status: 'error', message: 'Database read failure.' });
  }
});

// ─── Constant-time admin key check ───────────────────────────────────────────
function isValidAdminKey(providedKey) {
  const adminKey = process.env.ADMIN_API_KEY;
  if (!adminKey || !providedKey) return false;
  try {
    const a = Buffer.from(String(providedKey), 'utf8');
    const b = Buffer.from(String(adminKey),    'utf8');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch (_) {
    return false;
  }
}

// ─── GET /api/deposits (admin only) ──────────────────────────────────────────
app.get('/api/deposits', (req, res) => {
  if (!isValidAdminKey(req.headers['x-api-key'])) {
    return res.status(403).json({ status: 'error', message: 'Forbidden.' });
  }

  try {
    res.status(200).json(readJSON(DEPOSIT_FILE));
  } catch (e) {
    res.status(500).json({ status: 'error', message: 'Database read failure.' });
  }
});

// ─── POST /api/reset (admin only) ────────────────────────────────────────────
app.post('/api/reset', (req, res) => {
  if (!isValidAdminKey(req.headers['x-api-key'])) {
    return res.status(403).json({ status: 'error', message: 'Forbidden.' });
  }

  try {
    writeJSON(STATS_FILE,   { total: 0, donors: 0 });
    writeJSON(DEPOSIT_FILE, []);
    res.status(200).json({ status: 'success', message: 'Counter reset to zero.' });
  } catch (e) {
    res.status(500).json({ status: 'error', message: 'Reset failed.' });
  }
});

// Debug endpoint removed — it leaked the Safepay API key to any caller.

// ─── 404 catch-all ───────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ status: 'error', message: 'Route not found.' });
});

// ─── Global error handler ─────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('[unhandled error]', err.message);
  res.status(500).json({ status: 'error', message: 'Internal server error.' });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});