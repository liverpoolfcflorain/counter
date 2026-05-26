const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
require('dotenv').config();

const { Safepay } = require('@sfpy/node-sdk');

const app = express();

app.use(cors({ origin: '*' }));
app.use(express.json());

const PORT = process.env.PORT || 5001;
const DB_DIR = path.join(__dirname, 'safepay_db');
const STATS_FILE = path.join(DB_DIR, 'donation_stats.json');

if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
if (!fs.existsSync(STATS_FILE)) {
    fs.writeFileSync(STATS_FILE, JSON.stringify({ total: 145000, donors: 38 }, null, 2));
}

app.post('/api/checkout/safepay', async (req, res) => {
  try {
    const { amount } = req.body;
    const numericAmount = parseInt(amount, 10);

    if (isNaN(numericAmount) || numericAmount <= 0) {
      return res.status(400).json({ status: "error", message: "Invalid donation amount." });
    }

    const apiKey = process.env.SAFEPAY_SANDBOX_PUBLIC_KEY?.replace(/"/g, '');
    const v1Secret = process.env.SAFEPAY_SANDBOX_SECRET_KEY?.replace(/"/g, '');
    const webhookSecret = process.env.SAFEPAY_SANDBOX_WEBHOOK_SECRET?.replace(/"/g, '');

    console.log('API KEY:', apiKey);
    console.log('V1 SECRET:', v1Secret ? 'EXISTS' : 'MISSING');
    console.log('WEBHOOK SECRET:', webhookSecret ? 'EXISTS' : 'MISSING');

    const safepay = new Safepay({
      environment: 'sandbox',
      apiKey,
      v1Secret,
      webhookSecret
    });

    const { token } = await safepay.payments.create({
      amount: numericAmount,
      currency: 'PKR'
    });

    const checkoutUrl = safepay.checkout.create({
      token,
      orderId: `DON-${Date.now()}`,
      cancelUrl: 'https://counter-production-d72a.up.railway.app',
      redirectUrl: 'https://counter-production-d72a.up.railway.app',
      source: 'custom',
      webhooks: true
    });

    res.json({ status: "success", checkoutUrl });
  } catch (error) {
    console.error("Checkout error:", error.message);
    res.status(500).json({ status: "error", message: error.message });
  }
});

app.post('/api/webhooks/safepay', (req, res) => {
    const receivedSignature = req.headers['x-safepay-signature'];

    if (!receivedSignature) {
        return res.status(401).json({ status: "error", message: "Missing authorization signature." });
    }

    const webhookSecret = process.env.SAFEPAY_SANDBOX_WEBHOOK_SECRET?.replace(/"/g, '');
    const stringifiedPayload = JSON.stringify(req.body);
    const crypto = require('crypto');

    const localHash = crypto
        .createHmac('sha256', webhookSecret)
        .update(stringifiedPayload)
        .digest('hex');

    if (localHash !== receivedSignature) {
        return res.status(401).json({ status: "error", message: "Signature validation failed." });
    }

    const { data, event } = req.body;

    if (event === 'payment.succeeded') {
        const amount = parseInt(data.amount, 10);

        fs.readFile(STATS_FILE, 'utf8', (err, rawData) => {
            if (err) return res.status(500).send();

            let ledger = JSON.parse(rawData);
            ledger.total += amount;
            ledger.donors += 1;

            fs.writeFile(STATS_FILE, JSON.stringify(ledger, null, 2), () => {
                res.status(200).json({ status: "success" });
            });
        });
    } else {
        res.status(200).json({ status: "event_unhandled" });
    }
});

app.get('/api/donations', (req, res) => {
    fs.readFile(STATS_FILE, 'utf8', (err, rawData) => {
        if (err) return res.status(500).json({ status: "error", message: "Database read failure." });
        try {
            res.status(200).json(JSON.parse(rawData));
        } catch (e) {
            res.status(500).json({ status: "error", message: "JSON parse error." });
        }
    });
});

app.get('/api/debug', (req, res) => {
    const raw = process.env.SAFEPAY_SANDBOX_PUBLIC_KEY;
    const clean = raw?.replace(/"/g, '');
    res.json({
        raw,
        clean,
        rawLength: raw?.length,
        cleanLength: clean?.length
    });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
