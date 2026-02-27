app.post('/api/checkout-intent', async (req, res) => {
  try {
    const { plan, email } = req.body;

    if (!plan || !email) {
      return res.status(400).json({ success: false });
    }

    console.log(`Checkout started: ${plan} - ${email}`);

    return res.json({ success: true });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false });
  }
});
