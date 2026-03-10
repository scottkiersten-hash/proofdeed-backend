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
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import pkg from "pg";

const { Pool } = pkg;

const app = express();
const PORT = process.env.PORT || 8080;

/* ===========================
DATABASE
=========================== */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

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

app.get("/api/verify/:hash", async (req, res) => {

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

});

/* ===========================
GET CERTIFICATE
=========================== */

app.get("/api/certificate/:id", async (req, res) => {

  const { rows } = await pool.query(
    "SELECT * FROM certifications WHERE certification_id=$1",
    [req.params.id]
  );

  if (!rows.length) {
    return res.status(404).json({ error: "Certificate not found" });
  }

  res.json(rows[0]);

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

    const polygon_tx = await anchorToPolygon(hash);

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

  const document = "ProofDeed Test Document";

  const hash = crypto
    .createHash("sha256")
    .update(document)
    .digest("hex");

  const polygon_tx = await anchorToPolygon(hash);

  const timestamp = new Date().toISOString();
  const certification_id = "PD-" + Date.now();

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

});

/* ===========================
START SERVER
=========================== */

app.listen(PORT, () => {

  console.log("================================");
  console.log("ProofDeed backend running");
  console.log("Port:", PORT);
  console.log("================================");

});
