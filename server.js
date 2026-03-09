```javascript
import dotenv from "dotenv";
dotenv.config();

import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import Stripe from "stripe";

const app = express();
const PORT = process.env.PORT || 8080;

/* ===========================
STRIPE
=========================== */

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

/* ===========================
MIDDLEWARE
=========================== */

app.use(helmet());
app.use(cors());
app.use(express.json());

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
}));

/* ===========================
HEALTH CHECK
=========================== */

app.get("/", (req, res) => {
  res.send("ProofDeed backend running");
});

app.get("/api/health", (req, res) => {
  res.json({ status: "ok" });
});

/* ===========================
STRIPE WEBHOOK
=========================== */

app.post("/api/stripe-webhook", express.raw({ type: "application/json" }), (req, res) => {

  const sig = req.headers["stripe-signature"];

  let event;

  try {

    event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET
    );

  } catch (err) {

    console.log("Webhook signature failed:", err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);

  }

  /* EVENT HANDLING */

  if (event.type === "checkout.session.completed") {

    const session = event.data.object;

    console.log("Payment successful:", session.customer_email);

  }

  if (event.type === "invoice.payment_succeeded") {

    console.log("Subscription payment received");

  }

  if (event.type === "customer.subscription.deleted") {

    console.log("Subscription cancelled");

  }

  res.json({ received: true });

});

/* ===========================
START SERVER
=========================== */

app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});
```
