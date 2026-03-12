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

/* ---------------- Stripe ---------------- */

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

/* Stripe webhook requires raw body */
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

    if (event.type === "checkout.session.completed") {
      const session = event.data.object;

      const email = session.customer_details.email;
      const customerId = session.customer;

      try {
        const userCheck = await pool.query(
          "SELECT * FROM users WHERE email = $1",
          [email]
        );

        if (userCheck.rows.length === 0) {
          await pool.query(
            `INSERT INTO users (email, stripe_customer_id)
             VALUES ($1, $2)`,
            [email, customerId]
          );

          console.log("New user created:", email);
        }
      } catch (dbError) {
        console.log("Database error:", dbError);
      }
    }

    res.json({ received: true });
  }
);

/* ---------------- Normal Middleware ---------------- */

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

/* ---------------- Database ---------------- */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
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

/* ---------------- DATABASE FIX ENDPOINT ---------------- */

app.get("/api/fix-db", async (req, res) => {
  try {

    await pool.query(`
      ALTER TABLE certifications
      ADD COLUMN IF NOT EXISTS certification_id TEXT;
    `);

    res.json({
      success: true,
      message: "certification_id column created"
    });

  } catch (err) {

    res.status(500).json({
      success: false,
      error: err.message
    });

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
      VALUES ($1, $2, $3, $4, $5)
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

/* ---------------- Start Server ---------------- */

app.listen(port, () => {
  console.log(`ProofDeed backend running on port ${port}`);
});
