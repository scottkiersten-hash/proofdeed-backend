import dotenv from "dotenv";
dotenv.config();

import anchorToPolygon from "./polygon.js";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import Stripe from "stripe";
import OpenAI from "openai";
import crypto from "crypto";
import PDFDocument from "pdfkit";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const app = express();
const PORT = process.env.PORT || 8080;

/* ===========================
TEMP STORAGE
=========================== */

const users = [];
const certifications = [];

/* ===========================
INIT CLIENTS
=========================== */

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

/* ===========================
SECURITY
=========================== */

app.set("trust proxy", 1);

app.use(helmet());

app.use(cors({
  origin: [
    "https://proofdeed.com",
    "https://www.proofdeed.com",
    process.env.FRONTEND_URL
  ].filter(Boolean),
  credentials: true
}));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
}));

/* ======================================================
STRIPE WEBHOOK — MUST BE BEFORE ANY BODY PARSERS
====================================================== */

app.post(
  "/api/stripe-webhook",
  express.raw({ type: "*/*" }),
  (req, res) => {

    const sig = req.headers["stripe-signature"];

    let event;

    try {

      event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        process.env.STRIPE_WEBHOOK_SECRET
      );

    } catch (err) {

      console.error("Webhook verification failed:", err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);

    }

    console.log("Stripe event:", event.type);

    if (event.type === "checkout.session.completed") {

      const session = event.data.object;
      console.log("Payment completed:", session.id);

    }

    if (event.type === "invoice.payment_succeeded") {

      const invoice = event.data.object;
      console.log("Invoice paid:", invoice.id);

    }

    if (event.type === "customer.subscription.deleted") {

      const sub = event.data.object;
      console.log("Subscription cancelled:", sub.id);

    }

    res.json({ received: true });

  }
);

/* ======================================================
BODY PARSERS FOR NORMAL ROUTES
====================================================== */

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

/* ===========================
AUTH MIDDLEWARE
=========================== */

function authenticateToken(req, res, next) {

  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ error: "Token required" });
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, process.env.JWT_SECRET || "dev_secret", (err, user) => {

    if (err) {
      return res.status(403).json({ error: "Invalid token" });
    }

    req.user = user;
    next();

  });

}

/* ===========================
HEALTH
=========================== */

app.get("/", (req, res) => {
  res.status(200).send("ProofDeed backend running");
});

app.get("/api/health", (req, res) => {
  res.json({ status: "ok" });
});

/* ===========================
VERIFY CERTIFICATE (NEW)
=========================== */

app.get("/api/verify/:hash", (req, res) => {

  const cert = certifications.find(
    c => c.hash === req.params.hash
  );

  if (!cert) {
    return res.status(404).json({
      verified: false
    });
  }

  res.json({
    verified: true,
    certification_id: cert.certification_id,
    timestamp: cert.timestamp,
    hash: cert.hash
  });

});

/* ===========================
AI TEST ROUTE
=========================== */

app.get("/api/ai-test", async (req, res) => {

  try {

    const response = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: "You are ProofDeed AI." },
        { role: "user", content: "Say AI is connected." }
      ]
    });

    res.json({
      success: true,
      reply: response.choices[0].message.content
    });

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: "AI test failed"
    });

  }

});

/* ===========================
STRIPE CHECKOUT
=========================== */

app.get("/api/create-checkout-session", async (req, res) => {

  try {

    const { price } = req.query;

    const priceMap = {
      PRICE_STARTER_MONTHLY: process.env.PRICE_STARTER_MONTHLY,
      PRICE_STARTER_YEARLY: process.env.PRICE_STARTER_YEARLY,
      PRICE_PRO_MONTHLY: process.env.PRICE_PRO_MONTHLY,
      PRICE_PRO_YEARLY: process.env.PRICE_PRO_YEARLY
    };

    const stripePrice = priceMap[price];

    const session = await stripe.checkout.sessions.create({

      mode: "subscription",

      line_items: [
        {
          price: stripePrice,
          quantity: 1
        }
      ],

      success_url: "https://proofdeed.com/success?session_id={CHECKOUT_SESSION_ID}",
      cancel_url: "https://proofdeed.com/document",

      billing_address_collection: "auto"

    });

    res.redirect(303, session.url);

  } catch (error) {

    console.error("Stripe session error:", error);

    res.status(500).json({
      error: "Stripe session creation failed"
    });

  }

});

/* ===========================
CERTIFY DOCUMENT
=========================== */

app.post("/api/certify-document", authenticateToken, async (req, res) => {

  try {

    const { document } = req.body;

    const hash = crypto
      .createHash("sha256")
      .update(document)
      .digest("hex");

    await anchorToPolygon(hash);

    const timestamp = new Date().toISOString();
    const certification_id = "PD-" + Date.now();

    const ai = await openai.chat.completions.create({

      model: "gpt-4o-mini",

      messages: [
        {
          role: "system",
          content: "Extract structured data from legal documents and return JSON."
        },
        {
          role: "user",
          content: document
        }
      ],

      response_format: { type: "json_object" }

    });

    const extracted = JSON.parse(ai.choices[0].message.content);

  const polygon_tx = await anchorToPolygon(hash);

const record = {
  certification_id,
  timestamp,
  hash,
  polygon_tx,
  user_id: req.user.id,
  document_data: extracted
};

    certifications.push(record);

    res.json({
      success: true,
      certification_id,
      hash,
      timestamp,
      document_data: extracted
    });

  } catch (err) {

    console.error("Certification error:", err);

    res.status(500).json({
      error: "Certification failed"
    });

  }

});

/* ===========================
START SERVER
=========================== */

app.listen(PORT, () => {
  console.log("🚀 Server running on port " + PORT);
});
