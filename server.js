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
STRIPE WEBHOOK
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

    res.json({ received: true });

  }
);

/* ======================================================
BODY PARSERS
====================================================== */

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

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
POLYGON TEST ROUTE (NEW)
=========================== */

app.get("/api/test-cert", async (req, res) => {

  const document = "Test ProofDeed Document";

  const hash = crypto
    .createHash("sha256")
    .update(document)
    .digest("hex");

  const polygon_tx = await anchorToPolygon(hash);

  const timestamp = new Date().toISOString();
  const certification_id = "PD-" + Date.now();

  const record = {
    certification_id,
    timestamp,
    hash,
    polygon_tx,
    document_data: { test: true }
  };

  certifications.push(record);

  res.json(record);

});

/* ===========================
VERIFY CERTIFICATE
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
    hash: cert.hash,
    polygon_tx: cert.polygon_tx
  });

});

/* ===========================
START SERVER
=========================== */

app.listen(PORT, () => {
  console.log("🚀 Server running on port " + PORT);
});
