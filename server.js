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

/* ===========================
   STRIPE SAFE INIT
=========================== */

let stripe = null;

if (process.env.STRIPE_SECRET_KEY) {
  stripe = new Stripe(process.env.STRIPE_SECRET_KEY, {
    apiVersion: '2023-10-16',
  });
}

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
   HEALTH CHECKS
=========================== */

app.get('/', (req, res) => {
  res.status(200).send('ProofDeed backend running');
});

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

/* ===========================
   STRIPE CHECKOUT
=========================== */

app.post('/api/checkout-intent', async (req, res) => {
  try {
    if (!stripe) {
      return res.status(500).json({ error: 'Stripe not configured' });
    }

    const { plan, vertical } = req.body;

    if (!plan || !vertical) {
      return res.status(400).json({ error: 'Missing plan or vertical' });
    }

    const priceMap = {
      starter: 1900,
      pro: 3900
    };

    if (!priceMap[plan]) {
      return res.status(400).json({ error: 'Invalid plan' });
    }

    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      payment_method_types: ['card'],
      line_items: [
        {
          price_data: {
            currency: 'usd',
            product_data: {
              name: `ProofDeed ${plan} Plan`
            },
            unit_amount: priceMap[plan]
          },
          quantity: 1
        }
      ],
      success_url: `https://proofdeed.com/`,
      cancel_url: `https://proofdeed.com/${vertical}`
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

    // Basic email validation server-side
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

    // TODO: integrate Mailgun here later

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
