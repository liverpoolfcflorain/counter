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

// ==============================================================================
// 1. CHECKOUT SESSION INITIALIZATION ENDPOINT
// ==============================================================================
app.post('/api/checkout/safepay', (req, res) => {
    try {
        const { amount } = req.body;
        const numericAmount = parseInt(amount, 10);

        if (isNaN(numericAmount) || numericAmount < 1) {
            return res.status(400).json({ status: "error", message: "Invalid amount." });
        }

        // Construct production/sandbox URL scheme dynamically based on config
        const baseUrl = SAFEPAY_ENVIRONMENT === 'production' 
            ? 'https://checkout.getsafepay.com/' 
            : 'https://sandbox.api.getsafepay.com/checkout/render';

        // Build the query parameter matrix
        const queryParams = new URLSearchParams({
            env: SAFEPAY_ENVIRONMENT,
            beacon: SAFEPAY_API_KEY,
            amount: numericAmount,
            currency: 'PKR',
            webhooks: 'true' // Explicit instruction for Safepay to fire asynchronous posts
        });

        const targetCheckoutUrl = `${baseUrl}?${queryParams.toString()}`;

        res.status(200).json({
            status: "success",
            checkoutUrl: targetCheckoutUrl
        });

    } catch (globalError) {
        console.error("Session generation dropped:", globalError);
        res.status(500).json({ status: "error", message: "Internal encryption error mapping session link." });
    }
});

// ==============================================================================
// 2. SAFEPAY WEBHOOK INGESTION & SIGNATURE VALIDATOR
// ==============================================================================
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
                return res.status(200).json({ status: "success" });
            });
        });
    } else {
        return res.status(400).json({ status: "ignored", message: "Non-actionable event tracking parameter." });
    }
});

// ==============================================================================
// 3. REAL-TIME PUBLIC METRICS DISPATCH ENDPOINT (ADDED)
// ==============================================================================
app.get('/api/donations', (req, res) => {
    fs.readFile(STATS_FILE, 'utf8', (err, rawData) => {
        if (err) {
            console.error("Failed to read ledger registry data:", err);
            return res.status(500).json({ status: "error", message: "Database read failure." });
        }
        
        try {
            const currentLedgerStats = JSON.parse(rawData);
            return res.status(200).json(currentLedgerStats);
        } catch (parseError) {
            return res.status(500).json({ status: "error", message: "JSON serialization corrupt." });
        }
    });
});

// ==============================================================================
// RUN SERVER ENVIRONMENT
// ==============================================================================
app.listen(PORT, () => {
    console.log(`🚀 Automated Transaction Service active on container port: ${PORT}`);
});