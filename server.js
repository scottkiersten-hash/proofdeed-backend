import dotenv from "dotenv";
dotenv.config();

import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import Stripe from "stripe";
import OpenAI from "openai";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import pkg from "pg";

import anchorToPolygon from "./polygon.js";

const { Pool } = pkg;

const app = express();
const PORT = process.env.PORT || 8080;

/* ===========================
DATABASE
=========================== */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

/* ===========================
INIT CLIENTS
=========================== */

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

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

  const token = authHeader?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Token required" });
  }

  jwt.verify(
    token,
    process.env.JWT_SECRET,
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

app.get("/api/health", async (req, res) => {

  try {

    await pool.query("SELECT 1");

    res.json({
      status: "ok",
      database: "connected"
    });

  } catch (err) {

    res.status(500).json({
      status: "error",
      database: "disconnected"
    });

  }

});

/* ===========================
VERIFY CERTIFICATE
=========================== */

app.get("/api/verify/:hash", async (req, res) => {

  try {

    const { rows } = await pool.query(
      "SELECT * FROM certifications WHERE hash=$1",
      [req.params.hash]
    );

    if (!rows.length) {
      return res.status(404).json({ verified: false });
    }

    const cert = rows[0];

    res.json({
      verified: true,
      certification_id: cert.certification_id,
      timestamp: cert.timestamp,
      hash: cert.hash,
      polygon_tx: cert.polygon_tx
    });

  } catch (err) {

    console.error(err);

    res.status(500).json({ error: "Verification failed" });

  }

});

/* ===========================
GET CERTIFICATE
=========================== */

app.get("/api/certificate/:id", async (req, res) => {

  try {

    const { rows } = await pool.query(
      "SELECT * FROM certifications WHERE certification_id=$1",
      [req.params.id]
    );

    if (!rows.length) {
      return res.status(404).json({ error: "Certificate not found" });
    }

    res.json(rows[0]);

  } catch (err) {

    console.error(err);

    res.status(500).json({ error: "Database error" });

  }

});

/* ===========================
CERTIFY DOCUMENT
=========================== */

app.post("/api/certify-document", authenticateToken, async (req, res) => {

  try {

    const { document } = req.body;

    if (!document) {
      return res.status(400).json({ error: "Document required" });
    }

    /* Prevent extremely large documents */

    if (document.length > 200000) {
      return res.status(400).json({ error: "Document too large" });
    }

    const hash = crypto
      .createHash("sha256")
      .update(document)
      .digest("hex");

    /* Prevent duplicate certifications */

    const existing = await pool.query(
      "SELECT certification_id FROM certifications WHERE hash=$1",
      [hash]
    );

    if (existing.rows.length) {

      return res.json({
        duplicate: true,
        certification_id: existing.rows[0].certification_id
      });

    }

    const polygon_tx = await anchorToPolygon(hash);

    const timestamp = new Date().toISOString();

    /* Safer ID generation */

    const certification_id = "PD-" + crypto.randomUUID();

    /* AI extraction (non-critical) */

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

      try {
        extracted = JSON.parse(ai.choices[0].message.content);
      } catch {
        extracted = { raw: ai.choices[0].message.content };
      }

    } catch (err) {

      console.error("AI extraction failed");

      extracted = { ai_error: true };

    }

    await pool.query(
      `
      INSERT INTO certifications
      (certification_id, timestamp, hash, polygon_tx, user_id, document_data)
      VALUES ($1,$2,$3,$4,$5,$6)
      `,
      [
        certification_id,
        timestamp,
        hash,
        polygon_tx,
        req.user.id,
        extracted
      ]
    );

    res.json({
      certification_id,
      timestamp,
      hash,
      polygon_tx,
      document_data: extracted
    });

  } catch (err) {

    console.error(err);

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
    const certification_id = "PD-" + crypto.randomUUID();

    await pool.query(
      `
      INSERT INTO certifications
      (certification_id, timestamp, hash, polygon_tx, document_data)
      VALUES ($1,$2,$3,$4,$5)
      `,
      [
        certification_id,
        timestamp,
        hash,
        polygon_tx,
        { test: true }
      ]
    );

    res.json({
      certification_id,
      timestamp,
      hash,
      polygon_tx
    });

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: "Test certification failed"
    });

  }

});

/* ===========================
START SERVER
=========================== */

async function startServer() {

  try {

    await pool.query("SELECT 1");

    app.listen(PORT, () => {

      console.log("================================");
      console.log("ProofDeed backend running");
      console.log("Port:", PORT);
      console.log("================================");

    });

  } catch (err) {

    console.error("Database connection failed");
    console.error(err);

    process.exit(1);

  }

}

startServer();
