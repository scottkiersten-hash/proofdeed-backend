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

    console.log("Stripe event received:", event.type);

    res.json({ received: true });

  }
);

/* ===========================
BODY PARSERS
=========================== */

app.use(express.json({ limit: "4mb" }));
app.use(express.urlencoded({ extended: true }));

/* ===========================
AUTH
=========================== */

function authenticateToken(req, res, next) {

  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ error: "Token required" });
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(
    token,
    process.env.JWT_SECRET || "dev_secret",
    (err, user) => {

      if (err) {
        return res.status(403).json({ error: "Invalid token" });
      }

      req.user = user;
      next();

    }
  );

}

/* ===========================
HEALTH
=========================== */

app.get("/", (req, res) => {
  res.send("ProofDeed backend running");
});

app.get("/api/health", (req, res) => {
  res.json({ status: "ok" });
});

/* ===========================
VERIFY CERTIFICATE
=========================== */

app.get("/api/verify/:hash", (req, res) => {

  const cert = certifications.find(
    c => c.hash === req.params.hash
  );

  if (!cert) {
    return res.status(404).json({ verified: false });
  }

  res.json({
    verified: true,
    certification_id: cert.certification_id,
    timestamp: cert.timestamp,
    hash: cert.hash,
    polygon_tx: cert.polygon_tx || null
  });

});

/* ===========================
GET CERTIFICATE
=========================== */

app.get("/api/certificate/:id", (req, res) => {

  const cert = certifications.find(
    c => c.certification_id === req.params.id
  );

  if (!cert) {
    return res.status(404).json({
      error: "Certificate not found"
    });
  }

  res.json(cert);

});

/* ===========================
AI CONNECTION TEST
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

    console.error("AI error:", err);

    res.status(500).json({
      error: "AI connection failed"
    });

  }

});

/* ===========================
CERTIFY DOCUMENT
=========================== */

app.post("/api/certify-document", authenticateToken, async (req, res) => {

  try {

    const { document } = req.body;

    if (!document) {
      return res.status(400).json({
        error: "Document content required"
      });
    }

    /* HASH DOCUMENT */

    const hash = crypto
      .createHash("sha256")
      .update(document)
      .digest("hex");

    /* POLYGON ANCHOR */

    let polygon_tx = null;

    try {

      polygon_tx = await anchorToPolygon(hash);

    } catch (err) {

      console.error("Polygon anchor failed:", err);

    }

    const timestamp = new Date().toISOString();
    const certification_id = "PD-" + Date.now();

    /* AI EXTRACTION */

    let extracted = {};

    try {

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

      extracted = JSON.parse(ai.choices[0].message.content);

    } catch (err) {

      console.error("AI extraction failed:", err);

    }

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
      certification_id,
      timestamp,
      hash,
      polygon_tx,
      document_data: extracted
    });

  } catch (err) {

    console.error("Certification failed:", err);

    res.status(500).json({
      error: "Certification failed"
    });

  }

});

/* ===========================
TEST CERTIFICATE
=========================== */

app.get("/api/test-cert", async (req, res) => {

  try {

    const document = "ProofDeed Test Document";

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

  } catch (err) {

    console.error("Test cert error:", err);

    res.status(500).json({
      error: "Test certification failed"
    });

  }

});

/* ===========================
START SERVER
=========================== */

app.listen(PORT, () => {

  console.log("================================");
  console.log("ProofDeed backend running");
  console.log("Port:", PORT);
  console.log("Environment:", process.env.NODE_ENV || "development");
  console.log("================================");

});
