import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import pkg from "pg";
import crypto from "crypto";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import OpenAI from "openai";
import Stripe from "stripe";
import { anchorToPolygon } from "./polygon.js";

dotenv.config();

const { Pool } = pkg;

const app = express();
const port = process.env.PORT || 3000;

/* ---------------- Database ---------------- */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

/* ---------------- Stripe ---------------- */

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

/* Stripe webhook MUST be before express.json() */

app.post(
  "/api/stripe-webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {

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

    console.log("Stripe event received:", event.type);

    try {

      if (event.type === "checkout.session.completed") {

        const session = event.data.object;

        const email = session.customer_details?.email;
        const customerId = session.customer;

        if (!email) {
          return res.json({ received: true });
        }

        const userCheck = await pool.query(
          "SELECT * FROM users WHERE email = $1",
          [email]
        );

        if (userCheck.rows.length === 0) {

          await pool.query(
            `INSERT INTO users (email, stripe_customer_id)
             VALUES ($1,$2)`,
            [email, customerId]
          );

          console.log("New user created:", email);

        }

      }

    } catch (error) {

      console.log("Webhook DB error:", error);

    }

    res.status(200).json({ received: true });

  }
);

/* ---------------- Middleware ---------------- */

app.use(express.json());

app.use(
  cors({
    origin: process.env.FRONTEND_URL,
    credentials: true
  })
);

app.use(helmet());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});

app.use(limiter);

/* ---------------- Checkout Session ---------------- */

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

/* ---------------- OpenAI ---------------- */

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

/* ---------------- Auth ---------------- */

function authenticateToken(req, res, next) {

  const authHeader = req.headers["authorization"];

  if (!authHeader) {
    return res.sendStatus(401);
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {

    if (err) return res.sendStatus(403);

    req.user = user;
    next();

  });

}

/* ---------------- Health ---------------- */

app.get("/api/health", async (req, res) => {

  try {

    const result = await pool.query("SELECT NOW()");
    res.json({ status: "ok", database: result.rows[0] });

  } catch (err) {

    res.status(500).json({ error: err.message });

  }

});

/* ---------------- Test Certification ---------------- */

app.get("/api/test-cert", async (req, res) => {

  try {

    const testDocument = "ProofDeed test document " + Date.now();

    const hash = crypto.createHash("sha256").update(testDocument).digest("hex");

    const polygonTx = await anchorToPolygon(hash);

    const certificationId = "PD-" + Date.now();

    const result = await pool.query(
      `INSERT INTO certifications
      (certification_id, hash, polygon_tx, user_id, document_data)
      VALUES ($1,$2,$3,$4,$5)
      RETURNING *`,
      [
        certificationId,
        hash,
        polygonTx,
        0,
        JSON.stringify({
          test: true,
          document: testDocument
        })
      ]
    );

    res.json({
      success: true,
      certification: result.rows[0]
    });

  } catch (error) {

    res.status(500).json({
      success: false,
      error: error.message
    });

  }

});

/* ---------------- Certify Document ---------------- */

app.post("/api/certify-document", authenticateToken, async (req, res) => {

  try {

    const { document } = req.body;

    if (!document) {
      return res.status(400).json({ error: "Document required" });
    }

    const hash = crypto.createHash("sha256").update(document).digest("hex");

    const duplicateCheck = await pool.query(
      "SELECT * FROM certifications WHERE hash=$1",
      [hash]
    );

    if (duplicateCheck.rows.length > 0) {

      return res.json({
        message: "Document already certified",
        certification: duplicateCheck.rows[0]
      });

    }

    const polygonTx = await anchorToPolygon(hash);

    let extractedData = {};

    try {

      const aiResponse = await openai.chat.completions.create({
        model: "gpt-4o-mini",
        messages: [
          { role: "system", content: "Extract structured data from this document." },
          { role: "user", content: document }
        ]
      });

      extractedData = aiResponse.choices[0].message.content;

    } catch {

      console.log("AI extraction skipped");

    }

    const certificationId = "PD-" + Date.now();

    const result = await pool.query(
      `INSERT INTO certifications
      (certification_id, hash, polygon_tx, user_id, document_data)
      VALUES ($1,$2,$3,$4,$5)
      RETURNING *`,
      [
        certificationId,
        hash,
        polygonTx,
        req.user.id,
        JSON.stringify(extractedData)
      ]
    );

    res.json({
      success: true,
      certification: result.rows[0]
    });

  } catch (error) {

    res.status(500).json({
      error: "Certification failed",
      details: error.message
    });

  }

});

/* ---------------- Verify ---------------- */

app.get("/api/verify/:hash", async (req, res) => {

  try {

    const { hash } = req.params;

    const result = await pool.query(
      "SELECT * FROM certifications WHERE hash=$1",
      [hash]
    );

    if (result.rows.length === 0) {
      return res.json({ verified: false });
    }

    res.json({
      verified: true,
      certification: result.rows[0]
    });

  } catch (error) {

    res.status(500).json({ error: error.message });

  }

});

/* ---------------- Certificate ---------------- */

app.get("/api/certificate/:id", async (req, res) => {

  try {

    const { id } = req.params;

    const result = await pool.query(
      "SELECT * FROM certifications WHERE certification_id=$1",
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Certificate not found" });
    }

    res.json(result.rows[0]);

  } catch (error) {

    res.status(500).json({ error: error.message });

  }

});

/* ---------------- Start Server ---------------- */

app.listen(port, () => {
  console.log(`ProofDeed backend running on port ${port}`);
});
