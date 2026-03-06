import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import Stripe from 'stripe';
import OpenAI from 'openai';
import crypto from 'crypto';

const app = express();
const PORT = process.env.PORT || 8080;

/* ===========================
TEMP CERTIFICATE STORAGE
=========================== */

const certifications = [];

/* ===========================
ENV VALIDATION
=========================== */

if (!process.env.STRIPE_SECRET_KEY) {
  console.warn("⚠️ STRIPE_SECRET_KEY not set");
}

if (!process.env.FRONTEND_URL) {
  console.warn("⚠️ FRONTEND_URL not set");
}

if (!process.env.OPENAI_API_KEY) {
  console.warn("⚠️ OPENAI_API_KEY not set");
}

/* ===========================
INIT CLIENTS
=========================== */

const stripe = process.env.STRIPE_SECRET_KEY
  ? new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2023-10-16' })
  : null;

const openai = process.env.OPENAI_API_KEY
  ? new OpenAI({ apiKey: process.env.OPENAI_API_KEY })
  : null;

/* ===========================
SECURITY + MIDDLEWARE
=========================== */

app.set('trust proxy', 1);

app.use(helmet());
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

app.use(cors({
  origin: [
    'https://proofdeed.com',
    'https://www.proofdeed.com',
    process.env.FRONTEND_URL
  ].filter(Boolean),
  credentials: true
}));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
}));

/* ===========================
HEALTH
=========================== */

app.get('/', (req, res) => {
  res.status(200).send('ProofDeed backend running');
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

/* ===========================
CERTIFY DOCUMENT
=========================== */

app.post('/api/certify-document', async (req, res) => {

  try {

    if (!openai) {
      return res.status(500).json({ error: "OpenAI not configured" });
    }

    const { document } = req.body;

    if (!document) {
      return res.status(400).json({ error: "Document text required" });
    }

    /* HASH */

    const hash = crypto
      .createHash('sha256')
      .update(document)
      .digest('hex');

    const timestamp = new Date().toISOString();
    const certification_id = "PD-" + Date.now();

    /* AI EXTRACTION */

    const ai = await openai.chat.completions.create({

      model: "gpt-4o-mini",

      messages: [
        {
          role: "system",
          content: "Extract structured data from legal documents and return JSON."
        },
        {
          role: "user",
          content: document
        }
      ],

      response_format: { type: "json_object" }

    });

    const extracted = JSON.parse(ai.choices[0].message.content);

    /* STORE CERTIFICATION */

    const record = {
      certification_id,
      timestamp,
      hash,
      document_data: extracted
    };

    certifications.push(record);

    /* RESPONSE */

    return res.json({
      success: true,
      certification_id,
      hash,
      timestamp,
      document_data: extracted
    });

  } catch (err) {

    console.error("Certification error:", err);

    return res.status(500).json({
      error: "Certification failed"
    });

  }

});

/* ===========================
VIEW CERTIFICATE
=========================== */

app.get('/api/certificate/:id', (req, res) => {

  const cert = certifications.find(
    c => c.certification_id === req.params.id
  );

  if (!cert) {
    return res.status(404).json({
      error: "Certificate not found"
    });
  }

  res.json(cert);

});

/* ===========================
START SERVER
=========================== */

app.listen(PORT, () => {
  console.log("🚀 Server running on port " + PORT);
});
