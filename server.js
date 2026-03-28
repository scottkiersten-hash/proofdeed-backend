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

/* ---------------- CORS ---------------- */
const configuredOrigins = [
  process.env.FRONTEND_URL,
  process.env.FRONTEND_URL_ALT,
  "https://proofdeed.com",
  "https://www.proofdeed.com",
  "https://api.proofdeed.com",
  "https://urchin-app-e33ih.ondigitalocean.app"
].filter(Boolean).map((origin) => origin.trim());

const allowedOrigins = [...new Set(configuredOrigins)];

app.use(cors({
  origin: function(origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    console.log("Blocked CORS request from:", origin);
    return callback(new Error(`CORS blocked for origin: ${origin}`));
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true
}));

app.options("*", cors({
  origin: allowedOrigins,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true
}));

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
app.post(["/create-proof", "/api/create-proof"], async (req, res) => {
  try {
    const { documentHash } = req.body;
    console.log("BODY:", JSON.stringify(req.body));
    console.log("HASH:", documentHash, "LEN:", documentHash?.length);

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
app.post(["/contact", "/api/contact"], async (req, res) => {
  try {
    const { name, company, email, notes, request_type, subject, proofId, documentHash, timestamp } = req.body;

    if (!email || !name) {
      return res.status(400).json({ error: "Name and email are required." });
    }

    await pool.query(
      `INSERT INTO contact_submissions (name, company, email, notes, request_type, created_at)
       VALUES ($1, $2, $3, $4, $5, NOW())`,
      [name, company || null, email, notes || null, request_type || "contact"]
    );

    const mailgunDomain = process.env.MAILGUN_DOMAIN;
    const mailgunApiKey = process.env.MAILGUN_API_KEY;

    if (mailgunDomain && mailgunApiKey) {
      const isProofEmail = !!proofId;
      const emailSubject = subject || (isProofEmail ? "Your ProofDeed Certificate" : "ProofDeed Contact Confirmation");
      const emailBody = isProofEmail
        ? `Thank you for using ProofDeed.\n\nYour document has been permanently recorded on the Polygon blockchain.\n\nProof ID: ${proofId}\nDocument Hash: ${documentHash}\nTimestamp: ${timestamp}\n\nVerify your document at:\nhttps://proofdeed.com/verify\n\nProofDeed\nhttps://proofdeed.com`
        : `Thank you for contacting ProofDeed.\n\nWe received your message and will be in touch shortly.\n\nName: ${name}\nEmail: ${email}\nNotes: ${notes || "N/A"}\n\nProofDeed\nhttps://proofdeed.com`;

      try {
        await fetch(`https://api.mailgun.net/v3/${mailgunDomain}/messages`, {
          method: "POST",
          headers: {
            "Authorization": "Basic " + Buffer.from(`api:${mailgunApiKey}`).toString("base64"),
            "Content-Type": "application/x-www-form-urlencoded"
          },
          body: new URLSearchParams({
            from: process.env.MAIL_FROM || `ProofDeed <mailgun@${mailgunDomain}>`,
            to: email,
            subject: emailSubject,
            text: emailBody
          })
        });
        console.log(`Email sent to ${email}`);
      } catch (mailErr) {
        console.error("Mailgun error (non-fatal):", mailErr.message);
      }
    }

    console.log(`New ${request_type || "contact"} submission from: ${email}`);
    res.json({ success: true });

  } catch (error) {
    console.error("Contact form error:", error);
    res.status(500).json({ error: error.message });
  }
});

/* ---------------- STRIPE CHECKOUT ---------------- */
app.post(["/create-checkout-session", "/api/create-checkout-session"], async (req, res) => {
  try {
    const { plan, success_url, cancel_url } = req.body;

    const priceMap = {
      "starter-monthly": process.env.PRICE_STARTER_MONTHLY,
      "starter-annual":  process.env.PRICE_STARTER_YEARLY,
      "pro-monthly":     process.env.PRICE_PRO_MONTHLY,
      "pro-annual":      process.env.PRICE_PRO_YEARLY,
    };

    const priceId = priceMap[plan];
    if (!priceId) return res.status(400).json({ error: `Invalid plan: ${plan}` });

    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      payment_method_types: ["card"],
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: "https://proofdeed.com/success",
     cancel_url: "https://proofdeed.com",
    });

    res.json({ url: session.url });

  } catch (err) {
    console.error("Stripe error:", err);
    res.status(500).json({ error: err.message });
  }
});

/* ---------------- STRIPE WEBHOOK ---------------- */
app.post(["/stripe-webhook", "/api/stripe-webhook"], express.raw({ type: "application/json" }), async (req, res) => {
  const sig = req.headers["stripe-signature"];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error("Webhook signature failed:", err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    const email = session.customer_details?.email;
    const customerId = session.customer;
    const subscriptionId = session.subscription;

    console.log("New subscriber:", email);

    try {
      await pool.query(
        `INSERT INTO users (email, stripe_customer_id, subscription_id, created_at)
         VALUES ($1, $2, $3, NOW())
         ON CONFLICT (email) DO UPDATE
         SET stripe_customer_id = $2, subscription_id = $3`,
        [email, customerId, subscriptionId]
      );
    } catch (dbErr) {
      console.error("User creation failed:", dbErr.message);
    }
  }

  res.json({ received: true });
});

/* ---------------- Start Server ---------------- */
app.listen(PORT, () => {
  console.log(`ProofDeed backend running on port ${PORT}`);
});
