app.post("/api/create-checkout-session", async (req, res) => {

  try {

    const { priceId } = req.body;

    const session = await stripe.checkout.sessions.create({

      mode: "subscription",

      line_items: [
        {
          price: priceId,
          quantity: 1
        }
      ],

      customer_creation: "always",

      success_url: `${process.env.FRONTEND_URL}/certify`,
      cancel_url: `${process.env.FRONTEND_URL}/pricing`,

      allow_promotion_codes: true

    });

    res.json({ url: session.url });

  } catch (error) {

    console.log("Stripe checkout error:", error);

    res.status(500).json({
      error: "Checkout session failed"
    });

  }

});
