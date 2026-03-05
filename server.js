import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import Stripe from 'stripe';

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

if (!process.env.DO_AGENT_ID) {
  console.warn("⚠️ DO_AGENT_ID not set (AI agent disabled)");
}

if (!process.env.DO_AGENT_KEY) {
  console.warn("⚠️ DO_AGENT_KEY not set (AI agent disabled)");
}

/* ===========================
   STRIPE INIT
=========================== */

const stripe = process.env.STRIPE_SECRET_KEY
  ? new Stripe(process.env.STRIPE_SECRET_KEY, {
      apiVersion: '2023-10-16',
    })
  : null;

/* ===========================
   SECURITY & MIDDLEWARE
=========================== */

app.set('trust proxy', 1);

app.use(helmet());

app.use(cors({
  origin: [
    'https://proofdeed.com',
    'https://www.proofdeed.com',
    process.env.FRONTEND_URL
  ].filter(Boolean),
  credentials: true
}));

app.use(express.json({ limit: '2mb' }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});

app.use(limiter);

/* ===========================
   HEALTH
=========================== */

app.get('/', (req, res) => {
  res.status(200).send('ProofDeed backend running');
});

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

/* ===========================
   DIGITALOCEAN AI DOCUMENT ANALYSIS
=========================== */

async function analyzeDocument(documentText) {

  if (!process.env.DO_AGENT_ID || !process.env.DO_AGENT_KEY) {
    throw new Error("AI agent not configured");
  }

  const response = await fetch(
    `https://api.digitalocean.com/v2/gen-ai/agents/${process.env.DO_AGENT_ID}/responses`,
    {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${process.env.DO_AGENT_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        input: documentText
      })
    }
  );

  const data = await response.json();

  return data;
}

/* ===========================
   DOCUMENT ANALYSIS ENDPOINT
=========================== */

app.post('/api/analyze-document', async (req, res) => {

  try {

    const { document } = req.body;

    if (!document) {
      return res.status(400).json({
        error: "Document text required"
      });
    }

    const analysis = await analyzeDocument(document);

    return res.json({
      success: true,
      analysis
    });

  } catch (err) {

    console.error("AI analysis error:", err);

    return res.status(500).json({
      error: "Document analysis failed"
    });

  }

});

/* ===========================
   STRIPE SUBSCRIPTION CHECKOUT
=========================== */

app.post('/api/checkout', async (req, res) => {
  try {
    if (!stripe) {
      return res.status(500).json({ error: 'Stripe not configured' });
    }

    const { plan, billing, vertical } = req.body;

    if (!plan || !billing || !vertical) {
      return res.status(400).json({
        error: 'Missing plan, billing, or vertical'
      });
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

    if (
      !priceMap[plan] ||
      !priceMap[plan][billing]
    ) {
      return res.status(400).json({
        error: 'Invalid plan or billing cycle'
      });
    }

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [
        {
          price: priceMap[plan][billing],
          quantity: 1
        }
      ],
      success_url: `https://proofdeed.com/success`,
      cancel_url: `https://proofdeed.com/${vertical}`,
      allow_promotion_codes: true
    });

    return res.json({ url: session.url });

  } catch (err) {
    console.error('Stripe error:', err);
    return res.status(500).json({ error: 'Stripe session failed' });
  }
});

/* ===========================
   CONTACT FORM
=========================== */

app.post('/api/contact', async (req, res) => {
  try {
    const { name, organization, email, phone, vertical, message } = req.body;

    if (!name || !organization || !email || !message) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Invalid email address' });
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
      leadId: `PD-${Date.now()}`
    });

  } catch (err) {
    console.error('Contact error:', err);
    return res.status(500).json({ error: 'Contact request failed' });
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
  console.log(`🚀 Server running on port ${PORT}`);
});
