app.post('/api/checkout-intent', async (req, res) => {
  try {
    const { plan, vertical } = req.body;

    if (!plan || !vertical) {
      return res.status(400).json({ error: 'Missing plan or vertical' });
    }

    const priceMap = {
      starter: 1900,  // $19
      pro: 3900       // $39
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
      success_url: 'https://proofdeed.com/',
      cancel_url: `https://proofdeed.com/${vertical}`
    });

    return res.json({ url: session.url });

  } catch (err) {
    console.error('Stripe error:', err);
    return res.status(500).json({ error: 'Stripe session failed' });
  }
});
