import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

const app = express();
const PORT = process.env.PORT || 8080;

app.set('trust proxy', 1);

app.use(helmet());
app.use(cors());
app.use(express.json());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});
app.use(limiter);

/* -------------------- HEALTH CHECK -------------------- */

app.get('/', (req, res) => {
  res.send('ProofDeed backend running');
});

/* -------------------- CHECKOUT INTENT -------------------- */

import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

app.post('/api/checkout-intent', async (req, res) => {
  try {
    const { plan } = req.body;

    if (!plan) {
      return res.status(400).json({ error: 'Missing plan' });
    }

    const priceMap = {
      starter: 4900,
      pro: 9900,
      enterprise: 19900
    };

    if (!priceMap[plan]) {
      return res.status(400).json({ error: 'Invalid plan' });
    }

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'payment',
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
      success_url: 'https://proofdeed.com/success',
cancel_url: 'https://proofdeed.com/pricing'

    return res.json({ url: session.url });

  } catch (err) {
    console.error('Stripe error:', err);
    return res.status(500).json({ error: 'Stripe session failed' });
  }
});

/* -------------------- START SERVER -------------------- */

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
