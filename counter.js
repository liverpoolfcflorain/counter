/**
 * Decolonize Palestine — Secure Safepay Transaction Automation System
 * Architecture: Server-to-Server Session Router & Signature Webhook Validator
 */

const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const crypto = require('crypto');
require('dotenv').config();

const app = express();

app.use(cors({ origin: '*' }));
app.use(express.json());

const PORT = process.env.PORT || 5001;
const DB_DIR = path.join(__dirname, 'safepay_db');
const STATS_FILE = path.join(DB_DIR, 'donation_stats.json');

const SAFEPAY_API_KEY = process.env.SAFEPAY_API_KEY;
const SAFEPAY_SECRET_KEY = process.env.SAFEPAY_SECRET_KEY;
const SAFEPAY_WEBHOOK_SECRET = process.env.SAFEPAY_WEBHOOK_SECRET;
const SAFEPAY_ENVIRONMENT = process.env.SAFEPAY_ENVIRONMENT || 'sandbox';

if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
if (!fs.existsSync(STATS_FILE)) {
    fs.writeFileSync(STATS_FILE, JSON.stringify({ total: 145000, donors: 38 }, null, 2));
}

app.post('/api/checkout/safepay', (req, res) => {
    try {
        const { amount } = req.body;
        const numericAmount = parseInt(amount, 10);

        if (isNaN(numericAmount) || numericAmount <= 0) {
            return res.status(400).json({ status: "error", message: "Invalid donation transaction value." });
        }

        const trackingId = `ID-${Date.now()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;

        const checkoutParams = {
            environment: SAFEPAY_ENVIRONMENT,
            client: SAFEPAY_API_KEY,
            amount: numericAmount,
            currency: "PKR",
            unique_id: trackingId,
            redirect_url: "https://your-actual-frontend-url.com/palestine_site_v4.html"
        };

        const gatewayBaseUrl = SAFEPAY_ENVIRONMENT === "production"
            ? "https://checkout.getsafepay.pk/"
            : "https://sandbox.getsafepay.pk/";

        const secureSessionUrl = `${gatewayBaseUrl}?${new URLSearchParams(checkoutParams).toString()}`;

        res.json({ status: "success", checkoutUrl: secureSessionUrl });
    } catch (error) {
        console.error("Internal processing error:", error);
        res.status(500).json({ status: "error", message: "Could not create payment session." });
    }
});

app.post('/api/webhooks/safepay', (req, res) => {
    const receivedSignature = req.headers['x-safepay-signature'];

    if (!receivedSignature) {
        return res.status(401).json({ status: "error", message: "Missing authorization signature." });
    }

    const stringifiedPayload = JSON.stringify(req.body);

    const localCalculatedHash = crypto
        .createHmac('sha256', SAFEPAY_WEBHOOK_SECRET)
        .update(stringifiedPayload)
        .digest('hex');

    if (localCalculatedHash !== receivedSignature) {
        return res.status(401).json({ status: "error", message: "Cryptographic signature validation failed." });
    }

    const { data, event } = req.body;

    if (event === 'payment.succeeded') {
        const validatedChargeAmount = parseInt(data.amount, 10);

        fs.readFile(STATS_FILE, 'utf8', (err, rawData) => {
            if (err) return res.status(500).send();

            let ledger = JSON.parse(rawData);
            ledger.total += validatedChargeAmount;
            ledger.donors += 1;

            fs.writeFile(STATS_FILE, JSON.stringify(ledger, null, 2), () => {
                console.log(`✅ Webhook validated! Captured PKR ${validatedChargeAmount}. Current Total: Rs. ${ledger.total}`);
                res.status(200).json({ status: "success" });
            });
        });
    } else {
        res.status(200).json({ status: "event_unhandled_by_system" });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});