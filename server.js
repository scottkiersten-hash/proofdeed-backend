import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import Stripe from 'stripe';
import OpenAI from 'openai';

const app = express();
const PORT = process.env.PORT || 8080;

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
  res.status(200).json({ status: 'ok' });
});

/* ===========================
AI TEST ENDPOINT
=========================== */

app.post('/api/analyze-document', async (req, res) => {

  try {

    if (!openai) {
      return res.status(500).json({
        error: "OpenAI not configured"
      });
    }

    const response = await openai.chat.completions.create({
      model: "gpt-4o-mini",
     vconst { document } = req.body;

messages: [
  { role: "system", content: "You extract structured information from legal documents." },
  { role: "user", content: document }
]
    });

    return res.json({
      success: true,
      reply: response?.choices?.[0]?.message?.content || ""
    });

  } catch (err) {

    console.error("AI Error:", err);

    return res.status(500).json({
      error: "AI request failed"
    });

  }

});

/* ===========================
STRIPE CHECKOUT
=========================== */

app.post('/api/checkout', async (req, res) => {

  try {

    if (!stripe) {
      return res.status(500).json({
        error: "Stripe not configured"
      });
    }

    if (!req.body) {
      return res.status(400).json({
        error: "Invalid request body"
      });
    }

    let { plan, billing, vertical } = req.body;

    if (!plan || !billing || !vertical) {
      return res.status(400).json({
        error: 'Missing plan, billing, or vertical'
      });
    }

    if (plan === 'pro') {
      plan = 'professional';
    }

    if (billing === 'annual') {
      billing = 'yearly';
    }

    const priceMap = {

      starter: {
        monthly: process.env.PRICE_STARTER_MONTHLY,
        yearly: process.env.PRICE_STARTER_YEARLY
      },

      professional: {
        monthly: process.env.PRICE_PRO_MONTHLY,
        yearly: process.env.PRICE_PRO_YEARLY
      }

    };

    const priceId = priceMap?.[plan]?.[billing];

    if (!priceId) {
      return res.status(400).json({
        error: 'Invalid plan or billing cycle'
      });
    }

    const session = await stripe.checkout.sessions.create({

      mode: 'subscription',

      payment_method_types: ['card'],

      line_items: [
        {
          price: priceId,
          quantity: 1
        }
      ],

      success_url: "https://proofdeed.com/success",

      cancel_url: "https://proofdeed.com/" + vertical,

      allow_promotion_codes: true

    });

    return res.json({
      success: true,
      url: session.url
    });

  } catch (err) {

    console.error('Stripe error:', err);

    return res.status(500).json({
      error: err?.message || 'Stripe session failed'
    });

  }

});

/* ===========================
CONTACT FORM
=========================== */

app.post('/api/contact', async (req, res) => {

  try {

    if (!req.body) {
      return res.status(400).json({
        error: "Invalid request body"
      });
    }

    const { name, organization, email, phone, vertical, message } = req.body;

    if (!name || !organization || !email || !message) {
      return res.status(400).json({
        error: 'Missing required fields'
      });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!emailRegex.test(email)) {
      return res.status(400).json({
        error: 'Invalid email address'
      });
    }

    console.log('📩 New Contact Lead:', {
      name,
      organization,
      email,
      phone,
      vertical,
      message
    });

    return res.json({
      success: true,
      leadId: "PD-" + Date.now()
    });

  } catch (err) {

    console.error('Contact error:', err);

    return res.status(500).json({
      error: 'Contact request failed'
    });

  }

});

/* ===========================
GLOBAL ERROR HANDLER
=========================== */

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

/* ===========================
START SERVER
=========================== */

app.listen(PORT, () => {
  console.log("🚀 Server running on port " + PORT);
});
