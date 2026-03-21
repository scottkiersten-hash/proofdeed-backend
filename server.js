import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import pkg from "pg";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import OpenAI from "openai";
import Stripe from "stripe";
import { anchorToPolygon } from "./polygon.js";

dotenv.config();

const { Pool } = pkg;
const app = express();
app.set("trust proxy", 1);

/* ---------------- REQUIRED FOR DIGITALOCEAN ---------------- */
app.get("/health", (req, res) => {
  res.status(200).json({ status: "ok" });
});

const PORT = process.env.PORT || 8080;

/* ---------------- Database ---------------- */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

/* ---------------- Middleware ---------------- */
app.use(express.json({ limit: "5mb" }));

const configuredOrigins = [
  process.env.FRONTEND_URL,
  process.env.FRONTEND_URL_ALT,
  "https://proofdeed.com",
  "https://www.proofdeed.com"
].filter(Boolean).map((origin) => origin.trim());

const allowedOrigins = [...new Set(configuredOrigins)];

app.options("*", cors());
app.use(cors({
  origin(origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error(`CORS blocked for origin: ${origin}`));
  },
  credentials: true
}));

app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  crossOriginOpenerPolicy: { policy: "unsafe-none" }
}));

app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

/* ---------------- OpenAI ---------------- */
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

/* ---------------- Stripe ---------------- */
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

/* ---------------- Auth ---------------- */
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.sendStatus(401);
  const token = authHeader.split(" ")[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

/* ---------------- Health (API) ---------------- */
app.get("/api/health", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");
    res.json({ status: "ok", database: result.rows[0] });
  } catch (error) {
    res.status(500).json({ status: "error", error: error.message });
  }
});

/* ---------------- Test Certification ---------------- */
app.get("/api/test-cert", async (req, res) => {
  try {
    const testDocument = "ProofDeed test document " + Date.now();
    const hash = crypto.createHash("sha256").update(testDocument).digest("hex");
    res.json({ document: testDocument, hash });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/* ---------------- CREATE PROOF ---------------- */
app.post("/create-proof", async (req, res) => {
  try {
    const { documentHash } = req.body;

    if (!documentHash || typeof documentHash !== "string" || documentHash.length !== 64) {
      return res.status(400).json({ error: "Invalid document hash. Must be a 64-character SHA-256 hex string." });
    }

    const proofId = "PD-" + Date.now();
    const timestamp = new Date().toISOString();

    let polygon_tx = null;
    try {
      polygon_tx = await anchorToPolygon(documentHash);
    } catch (blockchainErr) {
      console.error("Blockchain anchoring failed (non-fatal):", blockchainErr.message);
    }

    await pool.query(
      `INSERT INTO certifications (certification_id, hash, polygon_tx, created_at)
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT (certification_id) DO NOTHING`,
      [proofId, documentHash, polygon_tx]
    );

    res.json({
      proofId,
      timestamp,
      polygon_tx,
      verificationText: "Your document fingerprint has been permanently recorded on the Polygon blockchain."
    });

  } catch (error) {
    console.error("Create proof error:", error);
    res.status(500).json({ error: error.message });
  }
});

/* ---------------- VERIFY CERTIFICATE ---------------- */
app.get("/api/verify/:certId", async (req, res) => {
  try {
    const { certId } = req.params;

    if (!certId) {
      return res.status(400).json({ success: false, error: "Certificate ID required." });
    }

    const result = await pool.query(
      `SELECT certification_id, hash, polygon_tx, created_at, document_data
       FROM certifications WHERE certification_id = $1`,
      [certId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Certificate not found." });
    }

    res.json({ success: true, certification: result.rows[0] });

  } catch (error) {
    console.error("Verify error:", error);
    res.status(500).json({ success: false, error: error.message });
  }
});

/* ---------------- CONTACT / AFFILIATE FORM ---------------- */
app.post("/api/contact", async (req, res) => {
  try {
    const { name, company, email, notes, request_type } = req.body;

    if (!email || !name) {
      return res.status(400).json({ error: "Name and email are required." });
    }

    await pool.query(
      `INSERT INTO contact_submissions (name, company, email, notes, request_type, created_at)
       VALUES ($1, $2, $3, $4, $5, NOW())`,
      [name, company || null, email, notes || null, request_type || "contact"]
    );

    console.log(`N
