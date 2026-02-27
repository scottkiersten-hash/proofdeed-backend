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

app.post('/api/checkout-intent', async (req, res) => {
  try {
    const { plan } = req.body;

    if (!plan) {
      return res.status(400).json({ error: 'Missing plan' });
    }

    console.log(`Checkout started: ${plan}`);

    return res.json({ success: true });

  } catch (err) {
    console.error('Checkout error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

/* -------------------- START SERVER -------------------- */

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
