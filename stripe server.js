require('dotenv').config();

const express = require('express');
const Stripe = require('stripe');
const cors = require('cors');

const app = express();

app.use(cors());
app.use(express.json());

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

app.post('/api/checkout', async (req, res) => {

  try {

    const { plan, billing, vertical, successUrl, cancelUrl } = req.body;

    const priceMap = {
      starter: process.env.PRICE_STARTER_MONTHLY,
      pro: process.env.PRICE_PRO_MONTHLY
    };

    const priceId = priceMap[plan];

    if (!priceId) {
      return res.status(400).json({ error: 'Invalid plan' });
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

      success_url: successUrl || `${process.env.FRONTEND_URL}/success`,
      cancel_url: cancelUrl || `${process.env.FRONTEND_URL}`,

      metadata: {
        vertical,
        plan
      }

    });

    res.json({ url: session.url });

  } catch (err) {

    console.error(err);
    res.status(500).json({ error: 'Stripe session failed' });

  }

});

const PORT = process.env.PORT || 8080;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
