import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import pkg from "pg";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import Stripe from "stripe";
import cron from "node-cron";
import PDFDocument from "pdfkit";
import QRCode from "qrcode";
import * as OTPAuth from "otpauth";

function verifyTOTP(secret, token) {
  try {
    const totp = new OTPAuth.TOTP({
      issuer: "ProofDeed",
      label: "admin",
      algorithm: "SHA1",
      digits: 6,
      period: 30,
      secret: OTPAuth.Secret.fromBase32(secret.toUpperCase()),
    });
    return totp.validate({ token, window: 1 }) !== null;
  } catch (err) {
    console.error("TOTP verify error — invalid ADMIN_TOTP_SECRET:", err.message);
    return false;
  }
}

function generateTOTPSecret() {
  return new OTPAuth.Secret().base32;
}

function getTOTPUri(secret) {
  const totp = new OTPAuth.TOTP({
    issuer: "ProofDeed",
    label: "admin",
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    secret: OTPAuth.Secret.fromBase32(secret.toUpperCase()),
  });
  return totp.toString();
}
import { anchorToPolygon } from "./polygon.js";

dotenv.config();

/* ---------------- ENV VALIDATION ---------------- */
const REQUIRED_ENV = [
  "DATABASE_URL",
  "JWT_SECRET",
  "STRIPE_SECRET_KEY",
  "STRIPE_WEBHOOK_SECRET",
  "PRICE_STARTER_MONTHLY",
  "PRICE_STARTER_YEARLY",
  "PRICE_PRO_MONTHLY",
  "PRICE_PRO_YEARLY",
  "PRICE_ENTERPRISE",
  "POLYGON_RPC_URL",
  "POLYGON_PRIVATE_KEY",
  "ADMIN_SECRET",
];

const missingEnv = REQUIRED_ENV.filter((key) => !process.env[key]);
if (missingEnv.length > 0) {
  console.error("FATAL: Missing required environment variables:\n  " + missingEnv.join("\n  "));
  process.exit(1);
}

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
  process.env.DO_APP_URL
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
  allowedHeaders: ["Content-Type", "Authorization", "X-API-Key"],
  credentials: true
}));

app.options("*", cors({
  origin: allowedOrigins,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-API-Key"],
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
// Exclude stripe-webhook from global JSON parsing — it needs raw body for signature verification
app.use((req, res, next) => {
  if (req.originalUrl === '/api/stripe-webhook' || req.originalUrl === '/stripe-webhook') {
    next();
  } else {
    express.json({ limit: "5mb" })(req, res, next);
  }
});

app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  crossOriginOpenerPolicy: { policy: "unsafe-none" }
}));

app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: "Too many requests. Please wait and try again." }
});

/* ---------------- OpenAI ---------------- */
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

/* ---------------- API Key Auth ---------------- */
async function authenticateApiKey(req, res, next) {
  const apiKey = req.headers["x-api-key"];
  if (!apiKey) {
    return res.status(401).json({ error: "API key required. Include X-API-Key header." });
  }

  try {
    const result = await pool.query(
      "SELECT * FROM api_keys WHERE api_key = $1 AND active = TRUE",
      [apiKey]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Invalid or inactive API key." });
    }

    const keyData = result.rows[0];

    if (keyData.used_this_month >= keyData.monthly_limit) {
      return res.status(429).json({
        error: "Monthly limit reached.",
        used: keyData.used_this_month,
        limit: keyData.monthly_limit
      });
    }

    req.apiKey = keyData;
    next();
  } catch (error) {
    res.status(500).json({ error: "Internal server error." });
  }
}

// Same as authenticateApiKey but does NOT block on limit — used for upgrade/billing endpoints
async function authenticateApiKeyNoLimit(req, res, next) {
  const apiKey = req.headers["x-api-key"];
  if (!apiKey) return res.status(401).json({ error: "API key required." });
  try {
    const result = await pool.query(
      "SELECT * FROM api_keys WHERE api_key = $1 AND active = TRUE",
      [apiKey]
    );
    if (result.rows.length === 0) return res.status(401).json({ error: "Invalid or inactive API key." });
    req.apiKey = result.rows[0];
    next();
  } catch (error) {
    res.status(500).json({ error: "Internal server error." });
  }
}

/* ---------------- Usage Notifications ---------------- */
async function checkAndNotifyUsage(keyData) {
  const { email, api_key, used_this_month, monthly_limit, notified_80, notified_100 } = keyData;
  const pct = used_this_month / monthly_limit;
  const mailgunDomain = process.env.MAILGUN_DOMAIN;
  const mailgunApiKey = process.env.MAILGUN_API_KEY;
  if (!mailgunDomain || !mailgunApiKey) return;

  const upgradeUrl = `https://proofdeed.com/api-dashboard`;

  if (pct >= 1.0 && !notified_100) {
    await pool.query("UPDATE api_keys SET notified_100 = TRUE WHERE api_key = $1", [api_key]);
    fetch("https://api.mailgun.net/v3/" + mailgunDomain + "/messages", {
      method: "POST",
      headers: {
        "Authorization": "Basic " + Buffer.from("api:" + mailgunApiKey).toString("base64"),
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        from: process.env.MAIL_FROM || "ProofDeed <noreply@" + mailgunDomain + ">",
        to: email,
        subject: "ProofDeed — Monthly limit reached. Your API is paused.",
        text: [
          "Your ProofDeed account has reached its monthly certification limit.",
          "",
          `Used: ${used_this_month.toLocaleString()} of ${monthly_limit.toLocaleString()} certifications`,
          "",
          "Your API will return 429 errors until you add more credits or upgrade your plan.",
          "",
          "Add more credits or upgrade now:",
          upgradeUrl,
          "",
          "Options:",
          "  • Buy 1,000 more credits — available in your dashboard",
          "  • Upgrade to a higher plan — increases your monthly limit permanently",
          "",
          "ProofDeed\nhttps://proofdeed.com"
        ].join("\n")
      })
    }).catch(err => console.error("Usage 100% email failed:", err.message));
  } else if (pct >= 0.8 && !notified_80) {
    await pool.query("UPDATE api_keys SET notified_80 = TRUE WHERE api_key = $1", [api_key]);
    fetch("https://api.mailgun.net/v3/" + mailgunDomain + "/messages", {
      method: "POST",
      headers: {
        "Authorization": "Basic " + Buffer.from("api:" + mailgunApiKey).toString("base64"),
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        from: process.env.MAIL_FROM || "ProofDeed <noreply@" + mailgunDomain + ">",
        to: email,
        subject: "ProofDeed — You've used 80% of your monthly certifications",
        text: [
          "Heads up — your ProofDeed account is approaching its monthly limit.",
          "",
          `Used: ${used_this_month.toLocaleString()} of ${monthly_limit.toLocaleString()} certifications (80%+)`,
          "",
          "To avoid interruption, consider adding more credits or upgrading your plan before you hit the limit.",
          "",
          "Manage your plan:",
          upgradeUrl,
          "",
          "ProofDeed\nhttps://proofdeed.com"
        ].join("\n")
      })
    }).catch(err => console.error("Usage 80% email failed:", err.message));
  }
}

/* ---------------- Report Usage to Stripe ---------------- */
async function reportUsageToStripe(subscriptionItemId, quantity) {
  try {
    await stripe.subscriptionItems.createUsageRecord(subscriptionItemId, {
      quantity,
      timestamp: Math.floor(Date.now() / 1000),
      action: "increment"
    });
    console.log("Stripe usage reported:", quantity, "for", subscriptionItemId);
  } catch (err) {
    console.error("Stripe usage report failed (non-fatal):", err.message);
  }
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
    res.status(500).json({ error: "Internal server error." });
  }
});

/* ---------------- MAGIC LINK - SEND ---------------- */
app.post(["/auth/magic-link", "/api/auth/magic-link"], authRateLimit, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || !email.includes("@")) {
      return res.status(400).json({ error: "Valid email required." });
    }

    const userCheck = await pool.query("SELECT * FROM users WHERE email = $1", [email]);

    if (userCheck.rows.length === 0) {
      return res.status(404).json({ error: "No account found for this email. Please purchase a plan first." });
    }

    const token = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

    await pool.query(
      "INSERT INTO magic_links (email, token, expires_at) VALUES ($1, $2, $3)",
      [email, token, expiresAt]
    );

    const magicLink = "https://proofdeed.com/auth/verify?token=" + token;
    const mailgunDomain = process.env.MAILGUN_DOMAIN;
    const mailgunApiKey = process.env.MAILGUN_API_KEY;

    if (mailgunDomain && mailgunApiKey) {
      await fetch("https://api.mailgun.net/v3/" + mailgunDomain + "/messages", {
        method: "POST",
        headers: {
          "Authorization": "Basic " + Buffer.from("api:" + mailgunApiKey).toString("base64"),
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
          from: process.env.MAIL_FROM || "ProofDeed <mailgun@" + mailgunDomain + ">",
          to: email,
          subject: "Your ProofDeed Sign-In Link",
          text: "Click the link below to sign in to ProofDeed.\n\nThis link expires in 15 minutes.\n\n" + magicLink + "\n\nIf you did not request this, please ignore this email.\n\nProofDeed\nhttps://proofdeed.com"
        })
      });
    }

    console.log("Magic link sent to " + email);
    res.json({ success: true });

  } catch (error) {
    console.error("Magic link error:", error);
    res.status(500).json({ error: "Internal server error." });
  }
});

/* ---------------- MAGIC LINK - VERIFY ---------------- */
app.get(["/auth/verify", "/api/auth/verify"], authRateLimit, async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.status(400).json({ error: "Token required." });

    const result = await pool.query(
      "SELECT * FROM magic_links WHERE token = $1 AND used = FALSE AND expires_at > NOW()",
      [token]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Link expired or already used. Please request a new one." });
    }

    const link = result.rows[0];
    const email = link.email;

    await pool.query("UPDATE magic_links SET used = TRUE WHERE id = $1", [link.id]);

    const userResult = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    const user = userResult.rows[0];

    const certCount = await pool.query(
      "SELECT COUNT(*) FROM certifications WHERE user_id = $1 AND created_at > date_trunc('month', NOW())",
      [user?.id || 0]
    );

    const used = parseInt(certCount.rows[0].count) || 0;
    const plan = user?.subscription_id ? "pro" : "starter";
    const certLimit = plan === "pro" ? 70 : 25;

    const jwtToken = jwt.sign(
      { email, userId: user?.id, plan },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      jwt: jwtToken,
      email,
      plan,
      certifications_used: used,
      certifications_limit: certLimit
    });

  } catch (error) {
    console.error("Verify error:", error);
    res.status(500).json({ error: "Internal server error." });
  }
});

/* ---------------- USER CERTIFICATIONS ---------------- */
app.get(["/user/certifications", "/api/user/certifications"], authenticateToken, async (req, res) => {
  try {
    const { email } = req.user;

    const userResult = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    const user = userResult.rows[0];

    const certs = await pool.query(
      "SELECT certification_id, hash, polygon_tx, created_at FROM certifications WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50",
      [user?.id || 0]
    );

    const certCount = await pool.query(
      "SELECT COUNT(*) FROM certifications WHERE user_id = $1 AND created_at > date_trunc('month', NOW())",
      [user?.id || 0]
    );

    const used = parseInt(certCount.rows[0].count) || 0;
    const plan = user?.subscription_id ? "pro" : "starter";
    const limit = plan === "pro" ? 70 : 25;

    res.json({ certifications: certs.rows, used, limit, plan });

  } catch (error) {
    console.error("User certifications error:", error);
    res.status(500).json({ error: "Internal server error." });
  }
});

/* ---------------- ENTERPRISE - GENERATE API KEY ---------------- */
app.post("/api/enterprise/generate-key", async (req, res) => {
  try {
    const adminSecret = req.headers["x-admin-secret"];
    if (adminSecret !== process.env.ADMIN_SECRET) {
      return res.status(401).json({ error: "Unauthorized." });
    }

    const { email, monthly_limit } = req.body;
    if (!email) return res.status(400).json({ error: "Email required." });

    const apiKey = "pd_live_" + crypto.randomBytes(32).toString("hex");

    // Create or get Stripe customer
    let stripeCustomerId = null;
    let stripeSubscriptionId = null;
    let stripeSubscriptionItemId = null;

    try {
      // Check if customer already exists
      const existing = await pool.query("SELECT stripe_customer_id FROM users WHERE email = $1", [email]);

      if (existing.rows.length > 0 && existing.rows[0].stripe_customer_id) {
        stripeCustomerId = existing.rows[0].stripe_customer_id;
      } else {
        // Create new Stripe customer
        const customer = await stripe.customers.create({ email });
        stripeCustomerId = customer.id;
      }

      // Create metered subscription
      const subscription = await stripe.subscriptions.create({
        customer: stripeCustomerId,
        items: [{ price: process.env.PRICE_ENTERPRISE }],
        payment_behavior: "default_incomplete",
        expand: ["latest_invoice.payment_intent"]
      });

      stripeSubscriptionId = subscription.id;
      stripeSubscriptionItemId = subscription.items.data[0].id;

      console.log("Enterprise Stripe subscription created:", stripeSubscriptionId);
    } catch (stripeErr) {
      console.error("Stripe subscription creation failed (non-fatal):", stripeErr.message);
    }

    // Save API key and user
    await pool.query(
      `INSERT INTO api_keys (email, api_key, plan, monthly_limit, used_this_month, stripe_subscription_item_id, active, created_at)
       VALUES ($1, $2, 'enterprise', $3, 0, $4, TRUE, NOW())
       ON CONFLICT (email) DO UPDATE SET api_key = $2, monthly_limit = $3, stripe_subscription_item_id = $4, active = TRUE`,
      [email, apiKey, monthly_limit || 1000, stripeSubscriptionItemId]
    );

    await pool.query(
      `INSERT INTO users (email, stripe_customer_id, subscription_id, created_at)
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT (email) DO UPDATE SET stripe_customer_id = $2, subscription_id = $3`,
      [email, stripeCustomerId, stripeSubscriptionId]
    );

    // Send welcome email
    const mailgunDomain = process.env.MAILGUN_DOMAIN;
    const mailgunApiKey = process.env.MAILGUN_API_KEY;

    if (mailgunDomain && mailgunApiKey) {
      await fetch("https://api.mailgun.net/v3/" + mailgunDomain + "/messages", {
        method: "POST",
        headers: {
          "Authorization": "Basic " + Buffer.from("api:" + mailgunApiKey).toString("base64"),
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
          from: process.env.MAIL_FROM || "ProofDeed <mailgun@" + mailgunDomain + ">",
          to: email,
          subject: "Your ProofDeed Enterprise API Key",
          text: "Welcome to ProofDeed Enterprise.\n\nYour API Key: " + apiKey + "\n\nBilling: Usage-based, billed monthly via Stripe. Graduated pricing starts at $0.76/cert.\n\nAPI Documentation: https://proofdeed.com/api-docs\n\nProofDeed\nhttps://proofdeed.com"
        })
      });
    }

    res.json({
      success: true,
      apiKey,
      email,
      monthly_limit: monthly_limit || 1000,
      stripe_customer_id: stripeCustomerId,
      stripe_subscription_id: stripeSubscriptionId
    });

  } catch (error) {
    console.error("Generate API key error:", error);
    res.status(500).json({ error: "Internal server error." });
  }
});

/* ---------------- ENTERPRISE - SINGLE CERTIFY ---------------- */
app.post("/api/v1/certify", authenticateApiKey, async (req, res) => {
  try {
    const { documentHash } = req.body;

    if (!documentHash || typeof documentHash !== "string" || documentHash.length !== 64) {
      return res.status(400).json({ error: "Invalid document hash. Must be a 64-character SHA-256 hex string." });
    }

    const proofId = "PD-" + Date.now();
    const timestamp = new Date().toISOString();

    await pool.query(
      `INSERT INTO certifications (certification_id, hash, polygon_tx, api_key_email, ip_address, created_at)
       VALUES ($1, $2, NULL, $3, $4, NOW())
       ON CONFLICT (certification_id) DO NOTHING`,
      [proofId, documentHash, req.apiKey.email, req.ip || req.headers["x-forwarded-for"] || null]
    );

    const updatedKey = await pool.query(
      "UPDATE api_keys SET used_this_month = used_this_month + 1 WHERE api_key = $1 RETURNING *",
      [req.apiKey.api_key]
    );

    // Report usage to Stripe for automatic billing
    if (req.apiKey.stripe_subscription_item_id) {
      await reportUsageToStripe(req.apiKey.stripe_subscription_item_id, 1);
    }

    // Check 80%/100% thresholds and notify
    if (updatedKey.rows.length > 0) {
      checkAndNotifyUsage(updatedKey.rows[0]).catch(() => {});
    }

    // Respond immediately — anchor to blockchain in background
    res.json({ proofId, timestamp, polygon_tx: null, hash: documentHash, used: req.apiKey.used_this_month + 1, limit: req.apiKey.monthly_limit });

    // Background webhook + blockchain anchor
    anchorToPolygon(documentHash).then(async (txHash) => {
      await pool.query(
        "UPDATE certifications SET polygon_tx = $1 WHERE certification_id = $2",
        [txHash, proofId]
      );
      if (req.apiKey.webhook_url) {
        fetch(req.apiKey.webhook_url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ proofId, documentHash, timestamp, polygon_tx: txHash, event: "certification.created" })
        }).catch((err) => console.error("Webhook delivery failed (non-fatal):", err.message));
      }
    }).catch((err) => {
      console.error("Background blockchain anchor failed for", proofId, err.message);
    });

  } catch (error) {
    console.error("Enterprise certify error:", error);
    res.status(500).json({ error: "Internal server error." });
  }
});

/* ---------------- ENTERPRISE - BATCH CERTIFY (ASYNC) ---------------- */

async function processBatchBackground(batchId, certRecords, apiKey) {
  let processed = 0, failed = 0;
  for (const cert of certRecords) {
    try {
      const txHash = await anchorToPolygon(cert.documentHash);
      await pool.query(
        `UPDATE certifications SET polygon_tx = $1 WHERE certification_id = $2`,
        [txHash, cert.proofId]
      );
      processed++;
    } catch (err) {
      console.error("Batch anchor failed for", cert.proofId, err.message);
      failed++;
    }
    await pool.query(
      `UPDATE batches SET processed = $1, failed = $2 WHERE batch_id = $3`,
      [processed, failed, batchId]
    );
  }

  await pool.query(
    `UPDATE batches SET status = 'completed', processed = $1, failed = $2 WHERE batch_id = $3`,
    [processed, failed, batchId]
  );

  if (apiKey.stripe_subscription_item_id && processed > 0) {
    await reportUsageToStripe(apiKey.stripe_subscription_item_id, processed);
  }

  // Fire client webhook if configured
  if (apiKey.webhook_url) {
    const batchResult = await pool.query(
      `SELECT certification_id, hash, polygon_tx, label, created_at FROM certifications WHERE batch_id = $1`,
      [batchId]
    );
    try {
      await fetch(apiKey.webhook_url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          event: "batch.completed",
          batchId,
          total: certRecords.length,
          processed,
          failed,
          results: batchResult.rows.map(r => ({
            proofId: r.certification_id,
            documentHash: r.hash,
            label: r.label,
            polygon_tx: r.polygon_tx,
            timestamp: r.created_at,
            verifyUrl: `https://proofdeed.com/verify/${r.certification_id}`
          }))
        })
      });
      await pool.query(`UPDATE batches SET webhook_notified = TRUE WHERE batch_id = $1`, [batchId]);
      console.log("Batch webhook fired for:", batchId);
    } catch (err) {
      console.error("Batch webhook failed (non-fatal):", err.message);
    }
  }
}

app.post("/api/v1/batch", authenticateApiKey, async (req, res) => {
  try {
    const { documents } = req.body;

    if (!Array.isArray(documents) || documents.length === 0) {
      return res.status(400).json({ error: "documents array required." });
    }
    if (documents.length > 1000) {
      return res.status(400).json({ error: "Maximum 1,000 documents per batch." });
    }

    const remaining = req.apiKey.monthly_limit - req.apiKey.used_this_month;
    if (documents.length > remaining) {
      return res.status(429).json({ error: `Batch size exceeds remaining limit. Remaining: ${remaining}` });
    }

    const batchId = "BATCH-" + Date.now() + "-" + crypto.randomBytes(4).toString("hex");
    const timestamp = new Date().toISOString();

    // Build cert records, skip invalid hashes immediately
    const certRecords = [];
    const invalid = [];
    for (const doc of documents) {
      const { documentHash, label, id } = doc;
      if (!documentHash || typeof documentHash !== "string" || documentHash.length !== 64) {
        invalid.push({ id, label, error: "Invalid SHA-256 hash" });
        continue;
      }
      const proofId = "PD-" + Date.now() + "-" + crypto.randomBytes(3).toString("hex");
      certRecords.push({ proofId, documentHash, label: label || id || null });
    }

    // Insert batch record
    await pool.query(
      `INSERT INTO batches (batch_id, email, status, total, processed, failed, created_at)
       VALUES ($1, $2, 'processing', $3, 0, 0, NOW())`,
      [batchId, req.apiKey.email, certRecords.length]
    );

    // Insert all certs immediately as pending (polygon_tx = null)
    for (const cert of certRecords) {
      await pool.query(
        `INSERT INTO certifications (certification_id, hash, polygon_tx, batch_id, label, api_key_email, ip_address, created_at)
         VALUES ($1, $2, NULL, $3, $4, $5, $6, NOW()) ON CONFLICT (certification_id) DO NOTHING`,
        [cert.proofId, cert.documentHash, batchId, cert.label, req.apiKey.email, req.ip || req.headers["x-forwarded-for"] || null]
      );
    }

    // Deduct usage immediately
    const updatedBatchKey = await pool.query(
      "UPDATE api_keys SET used_this_month = used_this_month + $1 WHERE api_key = $2 RETURNING *",
      [certRecords.length, req.apiKey.api_key]
    );

    // Check 80%/100% thresholds and notify
    if (updatedBatchKey.rows.length > 0) {
      checkAndNotifyUsage(updatedBatchKey.rows[0]).catch(() => {});
    }

    // Respond immediately — blockchain anchoring happens in background
    res.json({
      batchId,
      status: "processing",
      total: certRecords.length,
      invalid: invalid.length,
      statusUrl: `https://proofdeed.com/api/v1/batch/${batchId}`,
      results: certRecords.map(r => ({
        proofId: r.proofId,
        documentHash: r.documentHash,
        label: r.label,
        timestamp,
        polygon_tx: null,
        verifyUrl: `https://proofdeed.com/verify/${r.proofId}`
      })),
      ...(invalid.length > 0 && { invalidDocuments: invalid })
    });

    // Anchor to blockchain in background
    processBatchBackground(batchId, certRecords, req.apiKey)
      .catch(err => console.error("processBatchBackground error:", err.message));

  } catch (error) {
    console.error("Batch certify error:", error);
    res.status(500).json({ error: "Internal server error." });
  }
});

/* ---------------- BATCH STATUS ---------------- */
app.get("/api/v1/batch/:batchId", authenticateApiKey, async (req, res) => {
  try {
    const { batchId } = req.params;
    const batch = await pool.query(
      `SELECT * FROM batches WHERE batch_id = $1 AND email = $2`,
      [batchId, req.apiKey.email]
    );
    if (batch.rows.length === 0) {
      return res.status(404).json({ error: "Batch not found." });
    }
    const b = batch.rows[0];
    const certs = await pool.query(
      `SELECT certification_id, hash, polygon_tx, label, created_at FROM certifications WHERE batch_id = $1`,
      [batchId]
    );
    res.json({
      batchId: b.batch_id,
      status: b.status,
      total: b.total,
      processed: b.processed,
      failed: b.failed,
      webhookNotified: b.webhook_notified,
      createdAt: b.created_at,
      results: certs.rows.map(r => ({
        proofId: r.certification_id,
        documentHash: r.hash,
        label: r.label,
        polygon_tx: r.polygon_tx,
        anchored: !!r.polygon_tx,
        timestamp: r.created_at,
        verifyUrl: `https://proofdeed.com/verify/${r.certification_id}`
      }))
    });
  } catch (error) {
    console.error("Batch status error:", error);
    res.status(500).json({ error: "Internal server error." });
  }
});

/* ---------------- API USAGE ---------------- */
app.get("/api/v1/usage", authenticateApiKeyNoLimit, async (req, res) => {
  try {
    const recentBatches = await pool.query(
      `SELECT batch_id, status, total, processed, failed, created_at FROM batches WHERE email = $1 ORDER BY created_at DESC LIMIT 10`,
      [req.apiKey.email]
    );
    res.json({
      email: req.apiKey.email,
      plan: req.apiKey.plan,
      monthlyLimit: req.apiKey.monthly_limit,
      usedThisMonth: req.apiKey.used_this_month,
      remaining: req.apiKey.monthly_limit - req.apiKey.used_this_month,
      webhookUrl: req.apiKey.webhook_url || null,
      recentBatches: recentBatches.rows
    });
  } catch (error) {
    res.status(500).json({ error: "Internal server error." });
  }
});

/* ---------------- SET WEBHOOK URL ---------------- */
app.put("/api/v1/webhook", authenticateApiKeyNoLimit, async (req, res) => {
  try {
    const { webhookUrl } = req.body;
    if (webhookUrl && !webhookUrl.startsWith("https://")) {
      return res.status(400).json({ error: "Webhook URL must start with https://" });
    }
    await pool.query(
      `UPDATE api_keys SET webhook_url = $1 WHERE api_key = $2`,
      [webhookUrl || null, req.apiKey.api_key]
    );
    res.json({ success: true, webhookUrl: webhookUrl || null });
  } catch (error) {
    res.status(500).json({ error: "Internal server error." });
  }
});

/* ---------------- LIST CERTIFICATIONS ---------------- */
app.get("/api/v1/certificates", authenticateApiKeyNoLimit, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 500);
    const offset = parseInt(req.query.offset) || 0;
    const certs = await pool.query(
      `SELECT certification_id, hash, polygon_tx, label, batch_id, created_at
       FROM certifications
       WHERE certification_id LIKE 'PD-%'
       ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
      [limit, offset]
    );
    res.json({
      total: certs.rows.length,
      limit,
      offset,
      certificates: certs.rows.map(r => ({
        proofId: r.certification_id,
        documentHash: r.hash,
        label: r.label,
        batchId: r.batch_id,
        polygon_tx: r.polygon_tx,
        anchored: !!r.polygon_tx,
        timestamp: r.created_at,
        verifyUrl: `https://proofdeed.com/verify/${r.certification_id}`,
        pdfUrl: `https://proofdeed.com/api/v1/certificate/${r.certification_id}/pdf`
      }))
    });
  } catch (error) {
    res.status(500).json({ error: "Internal server error." });
  }
});

/* ---------------- CERTIFICATE PDF DOWNLOAD ---------------- */
app.get("/api/v1/certificate/:proofId/pdf", authenticateApiKeyNoLimit, async (req, res) => {
  try {
    const { proofId } = req.params;
    const result = await pool.query(
      `SELECT certification_id, hash, polygon_tx, label, created_at FROM certifications WHERE certification_id = $1`,
      [proofId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Certificate not found." });
    }
    const cert = result.rows[0];

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="ProofDeed-${proofId}.pdf"`);

    const orgName = req.apiKey.organization_name || null;

    const doc = new PDFDocument({ margin: 60, size: "A4" });
    doc.pipe(res);

    // Header bar
    doc.rect(0, 0, doc.page.width, 80).fill("#0f172a");
    if (orgName) {
      doc.fontSize(22).font("Helvetica-Bold").fillColor("#ffffff").text(orgName.toUpperCase(), 60, 22);
      doc.fontSize(8).font("Helvetica").fillColor("#94a3b8").text("Powered by ProofDeed", 60, 48);
      doc.fontSize(8).font("Helvetica").fillColor("#64748b").text("Cryptographic Document Certificate", 60, 60);
    } else {
      doc.fontSize(22).font("Helvetica-Bold").fillColor("#ffffff").text("PROOFDEED", 60, 28);
      doc.fontSize(9).font("Helvetica").fillColor("#94a3b8").text("Cryptographic Document Certificate", 60, 54);
    }

    // Title
    doc.moveDown(3);
    doc.fontSize(16).font("Helvetica-Bold").fillColor("#0f172a").text("Certificate of Document Integrity", { align: "center" });
    doc.moveDown(0.5);
    doc.fontSize(9).font("Helvetica").fillColor("#64748b").text("This certificate confirms the existence and integrity of a document at the time of certification.", { align: "center" });

    doc.moveDown(1.5);
    doc.moveTo(60, doc.y).lineTo(doc.page.width - 60, doc.y).strokeColor("#e2e8f0").lineWidth(1).stroke();
    doc.moveDown(1);

    // Fields
    const fields = [
      { label: "Proof ID", value: cert.certification_id },
      { label: "Document Label", value: cert.label || "—" },
      { label: "SHA-256 Hash", value: cert.hash },
      { label: "Timestamp (UTC)", value: new Date(cert.created_at).toUTCString() },
      { label: "Blockchain", value: "Polygon (MATIC) Mainnet" },
      { label: "Transaction Hash", value: cert.polygon_tx || "Pending confirmation" },
      { label: "Verification URL", value: `https://proofdeed.com/verify/${cert.certification_id}` },
    ];

    for (const field of fields) {
      doc.fontSize(8).font("Helvetica-Bold").fillColor("#64748b").text(field.label.toUpperCase(), 60);
      doc.fontSize(10).font("Helvetica").fillColor("#0f172a").text(field.value, 60, doc.y + 2, { width: doc.page.width - 120, lineBreak: true });
      doc.moveDown(0.8);
    }

    doc.moveDown(1);
    doc.moveTo(60, doc.y).lineTo(doc.page.width - 60, doc.y).strokeColor("#e2e8f0").lineWidth(1).stroke();
    doc.moveDown(1);

    // Footer note
    doc.fontSize(8).font("Helvetica").fillColor("#94a3b8").text(
      "This certificate was generated by ProofDeed (proofdeed.com). The SHA-256 hash uniquely identifies the document at the time of certification. The blockchain transaction provides independent, tamper-evident, and permanent proof of existence. This certificate may be verified by any party at any time without access to ProofDeed systems.",
      60, doc.y, { width: doc.page.width - 120, align: "left" }
    );

    // Bottom bar
    const bottomY = doc.page.height - 40;
    doc.rect(0, bottomY, doc.page.width, 40).fill("#0f172a");
    doc.fontSize(8).font("Helvetica").fillColor("#94a3b8").text(
      `ProofDeed • proofdeed.com • ${new Date().getFullYear()}`,
      60, bottomY + 14
    );

    doc.end();
  } catch (error) {
    console.error("PDF generation error:", error);
    res.status(500).json({ error: "Internal server error." });
  }
});

/* ---------------- CREATE PROOF ---------------- */
app.post(["/create-proof", "/api/create-proof"], async (req, res) => {
  try {
    const { documentHash } = req.body;

    if (!documentHash || typeof documentHash !== "string" || documentHash.length !== 64) {
      return res.status(400).json({ error: "Invalid document hash. Must be a 64-character SHA-256 hex string." });
    }

    // Require a valid JWT — no anonymous certifications
    const authHeader = req.headers["authorization"];
    if (!authHeader) {
      return res.status(401).json({ error: "Authentication required." });
    }

    let decoded;
    try {
      const token = authHeader.split(" ")[1];
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ error: "Invalid or expired session. Please sign in again." });
    }

    const userResult = await pool.query("SELECT * FROM users WHERE email = $1", [decoded.email]);
    if (userResult.rows.length === 0) {
      return res.status(401).json({ error: "User not found." });
    }
    const user = userResult.rows[0];
    const userId = user.id;

    // Enforce plan limits
    const plan = user.subscription_id ? "pro" : "starter";
    const certLimit = plan === "pro" ? 70 : 25;
    const usedCount = await pool.query(
      "SELECT COUNT(*) FROM certifications WHERE user_id = $1 AND created_at > date_trunc('month', NOW())",
      [userId]
    );
    const used = parseInt(usedCount.rows[0].count) || 0;
    if (used >= certLimit) {
      return res.status(429).json({
        error: "Monthly certification limit reached. Please upgrade your plan.",
        used,
        limit: certLimit,
        plan
      });
    }

    const proofId = "PD-" + Date.now();
    const timestamp = new Date().toISOString();

    await pool.query(
      `INSERT INTO certifications (certification_id, hash, polygon_tx, user_id, created_at)
       VALUES ($1, $2, $3, $4, NOW())
       ON CONFLICT (certification_id) DO NOTHING`,
      [proofId, documentHash, null, userId]
    );

    // Respond immediately — anchor to blockchain in background
    res.json({
      proofId,
      timestamp,
      polygon_tx: null,
      verificationText: "Your document fingerprint has been permanently recorded on the Polygon blockchain."
    });

    // Certificate delivery email
    const mailgunDomain = process.env.MAILGUN_DOMAIN;
    const mailgunApiKey = process.env.MAILGUN_API_KEY;
    if (mailgunDomain && mailgunApiKey && user.email) {
      fetch("https://api.mailgun.net/v3/" + mailgunDomain + "/messages", {
        method: "POST",
        headers: {
          "Authorization": "Basic " + Buffer.from("api:" + mailgunApiKey).toString("base64"),
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
          from: process.env.MAIL_FROM || "ProofDeed <info@proofdeed.com>",
          to: user.email,
          subject: "ProofDeed Certificate — " + proofId,
          text: [
            "Your document has been certified and permanently anchored to the Polygon blockchain.",
            "",
            "Certificate ID: " + proofId,
            "SHA-256 Hash:   " + documentHash,
            "Certified:      " + new Date(timestamp).toUTCString(),
            "",
            "Verify this certificate at any time:",
            "https://proofdeed.com/verify/" + proofId,
            "",
            "This certificate is court-admissible under FRE Rule 901. Keep this email as your record.",
            "",
            "ProofDeed",
            "https://proofdeed.com"
          ].join("\n")
        })
      }).catch(err => console.error("Cert delivery email failed:", err.message));
    }

    // Usage warning for JWT users (80% and 100%)
    const newUsed = used + 1;
    const pct = newUsed / certLimit;
    if (pct >= 1.0) {
      fetch("https://api.mailgun.net/v3/" + mailgunDomain + "/messages", {
        method: "POST",
        headers: {
          "Authorization": "Basic " + Buffer.from("api:" + mailgunApiKey).toString("base64"),
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
          from: process.env.MAIL_FROM || "ProofDeed <info@proofdeed.com>",
          to: user.email,
          subject: "ProofDeed — Monthly limit reached",
          text: [
            "You have used all " + certLimit + " certifications in your plan this month.",
            "",
            "Your account is now paused until your limit resets on the 1st of next month.",
            "",
            "To certify more documents now, upgrade your plan:",
            "https://proofdeed.com/#pricing",
            "",
            "ProofDeed",
            "https://proofdeed.com"
          ].join("\n")
        })
      }).catch(() => {});
    } else if (pct >= 0.8) {
      fetch("https://api.mailgun.net/v3/" + mailgunDomain + "/messages", {
        method: "POST",
        headers: {
          "Authorization": "Basic " + Buffer.from("api:" + mailgunApiKey).toString("base64"),
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
          from: process.env.MAIL_FROM || "ProofDeed <info@proofdeed.com>",
          to: user.email,
          subject: "ProofDeed — You've used 80% of your monthly certifications",
          text: [
            "Heads up — you've used " + newUsed + " of " + certLimit + " certifications this month.",
            "",
            "To avoid interruption, consider upgrading your plan before you hit the limit:",
            "https://proofdeed.com/#pricing",
            "",
            "Your limit resets on the 1st of each month.",
            "",
            "ProofDeed",
            "https://proofdeed.com"
          ].join("\n")
        })
      }).catch(() => {});
    }

    // Background blockchain anchoring — updates DB when confirmed
    anchorToPolygon(documentHash).then(async (txHash) => {
      await pool.query(
        "UPDATE certifications SET polygon_tx = $1 WHERE certification_id = $2",
        [txHash, proofId]
      );
      console.log("Blockchain anchor confirmed for", proofId, txHash);
    }).catch((err) => {
      console.error("Background blockchain anchor failed for", proofId, err.message);
    });

  } catch (error) {
    console.error("Create proof error:", error);
    res.status(500).json({ error: "Internal server error." });
  }
});

/* ---------------- VERIFY CERTIFICATE ---------------- */
app.get(["/verify/:certId", "/api/verify/:certId"], async (req, res) => {
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
    const { name, company, organization, email, notes, message, phone, request_type, subject, proofId, documentHash, timestamp } = req.body;
    const resolvedCompany = company || organization || null;
    const resolvedNotes = notes || message || null;

    if (!email || !name) {
      return res.status(400).json({ error: "Name and email are required." });
    }

    await pool.query(
      `INSERT INTO contact_submissions (name, company, email, notes, request_type, created_at)
       VALUES ($1, $2, $3, $4, $5, NOW())`,
      [name, resolvedCompany, email, resolvedNotes, request_type || "contact"]
    );

    const mailgunDomain = process.env.MAILGUN_DOMAIN;
    const mailgunApiKey = process.env.MAILGUN_API_KEY;

    if (request_type === "affiliate") {
      try {
        const code = name.split(' ')[0].toUpperCase() + Math.floor(1000 + Math.random() * 9000);
        await pool.query(
          `INSERT INTO users (email, referral_code, created_at)
           VALUES ($1, $2, NOW())
           ON CONFLICT (email) DO UPDATE SET referral_code = $2`,
          [email, code]
        );
        if (mailgunDomain && mailgunApiKey) {
          const affiliateHtml = "<!DOCTYPE html><html><body style='margin:0;padding:0;background:#f0f0ee;font-family:Georgia,serif;'><div style='max-width:600px;margin:40px auto;background:#ffffff;border:1px solid #ddd;border-radius:4px;overflow:hidden;'><div style='height:4px;background:linear-gradient(90deg,#1a3a8e,#4080d0,#1a3a8e);'></div><div style='padding:40px;'><h1 style='font-size:22px;font-weight:700;color:#111;margin:0 0 8px;'>Welcome to ProofDeed Affiliates</h1><p style='font-size:14px;color:#666;margin:0 0 32px;'>Your affiliate account is ready. Start sharing your unique referral link below.</p><div style='background:#f8f8f6;border:1px solid #e5e5e5;border-radius:4px;padding:24px;margin-bottom:24px;'><p style='font-size:11px;font-weight:700;color:#999;text-transform:uppercase;letter-spacing:0.1em;margin:0 0 6px;'>Your Referral Code</p><p style='font-size:24px;font-family:monospace;color:#1a3a8e;font-weight:700;margin:0 0 20px;'>" + code + "</p><p style='font-size:11px;font-weight:700;color:#999;text-transform:uppercase;letter-spacing:0.1em;margin:0 0 6px;'>Your Referral Links</p><p style='font-size:13px;font-family:monospace;color:#333;margin:0 0 8px;'>https://proofdeed.com/auto?ref=" + code + "</p><p style='font-size:13px;font-family:monospace;color:#333;margin:0 0 8px;'>https://proofdeed.com/document?ref=" + code + "</p></div><p style='font-size:14px;color:#555;margin:0 0 16px;'>Every customer who signs up through your link will be tracked automatically.</p><p style='font-size:14px;color:#555;margin:0 0 32px;'>Questions? Contact us at <a href=\"mailto:info@proofdeed.com\" style=\"color:#1a3a8e;\">info@proofdeed.com</a></p><hr style='border:none;border-top:1px solid #e5e5e5;margin:24px 0;'><p style='font-size:12px;color:#999;font-family:sans-serif;margin:0;'>ProofDeed &mdash; Blockchain Document Certification</p></div><div style='height:4px;background:linear-gradient(90deg,#1a3a8e,#4080d0,#1a3a8e);'></div></div></body></html>";
          await fetch("https://api.mailgun.net/v3/" + mailgunDomain + "/messages", {
            method: "POST",
            headers: {
              "Authorization": "Basic " + Buffer.from("api:" + mailgunApiKey).toString("base64"),
              "Content-Type": "application/x-www-form-urlencoded"
            },
            body: new URLSearchParams({
              from: process.env.MAIL_FROM || "ProofDeed <mailgun@" + mailgunDomain + ">",
              to: email,
              subject: "Your ProofDeed Affiliate Code - " + code,
              html: affiliateHtml
            })
          });
          console.log("Affiliate code " + code + " sent to " + email);
        }
      } catch (affiliateErr) {
        console.error("Affiliate setup error (non-fatal):", affiliateErr.message);
      }
    }

    if (mailgunDomain && mailgunApiKey) {
      const isProofEmail = !!proofId;
      const emailSubject = subject || (isProofEmail ? "Your ProofDeed Certificate" : "ProofDeed Contact Confirmation");

      const htmlProofEmail = "<!DOCTYPE html><html><body style='margin:0;padding:0;background:#f0f0ee;font-family:Georgia,serif;'><div style='max-width:600px;margin:40px auto;background:#ffffff;border:1px solid #ddd;border-radius:4px;overflow:hidden;'><div style='height:4px;background:linear-gradient(90deg,#1a3a8e,#4080d0,#1a3a8e);'></div><div style='padding:40px;'><h1 style='font-size:22px;font-weight:700;color:#111;margin:0 0 8px;'>Document Certified</h1><p style='font-size:14px;color:#666;margin:0 0 32px;'>Your document has been permanently recorded on the Polygon blockchain.</p><div style='background:#f8f8f6;border:1px solid #e5e5e5;border-radius:4px;padding:24px;margin-bottom:24px;'><p style='font-size:11px;font-weight:700;color:#999;text-transform:uppercase;letter-spacing:0.1em;margin:0 0 6px;'>Proof ID</p><p style='font-size:18px;font-family:monospace;color:#1a3a8e;font-weight:700;margin:0 0 20px;'>" + proofId + "</p><p style='font-size:11px;font-weight:700;color:#999;text-transform:uppercase;letter-spacing:0.1em;margin:0 0 6px;'>Document Hash</p><p style='font-size:11px;font-family:monospace;color:#333;word-break:break-all;margin:0 0 20px;'>" + documentHash + "</p><p style='font-size:11px;font-weight:700;color:#999;text-transform:uppercase;letter-spacing:0.1em;margin:0 0 6px;'>Timestamp</p><p style='font-size:13px;color:#333;margin:0;'>" + timestamp + "</p></div><a href='https://proofdeed.com/verify' style='display:inline-block;background:#0f172a;color:#ffffff;text-decoration:none;padding:14px 28px;border-radius:6px;font-family:sans-serif;font-size:14px;font-weight:600;margin-bottom:24px;'>Verify Certificate</a><hr style='border:none;border-top:1px solid #e5e5e5;margin:24px 0;'><p style='font-size:12px;color:#999;font-family:sans-serif;margin:0;'>ProofDeed &mdash; Blockchain Document Certification</p><p style='font-size:12px;color:#999;font-family:sans-serif;margin:4px 0 0;'><a href='https://proofdeed.com' style='color:#1a3a8e;'>proofdeed.com</a></p></div><div style='height:4px;background:linear-gradient(90deg,#1a3a8e,#4080d0,#1a3a8e);'></div></div></body></html>";

      const textContactEmail = "New contact submission from ProofDeed.\n\nName: " + name + "\nEmail: " + email + "\nOrganization: " + (resolvedCompany || "N/A") + "\nPhone: " + (phone || "N/A") + "\nMessage: " + (resolvedNotes || "N/A") + "\n\nProofDeed\nhttps://proofdeed.com";

      try {
        const mailParams = {
          from: process.env.MAIL_FROM || "ProofDeed <mailgun@" + mailgunDomain + ">",
          to: process.env.MAIL_TO || email,
          subject: emailSubject,
        };

        if (isProofEmail) {
          mailParams.html = htmlProofEmail;
        } else {
          mailParams.text = textContactEmail;
        }

        await fetch("https://api.mailgun.net/v3/" + mailgunDomain + "/messages", {
          method: "POST",
          headers: {
            "Authorization": "Basic " + Buffer.from("api:" + mailgunApiKey).toString("base64"),
            "Content-Type": "application/x-www-form-urlencoded"
          },
          body: new URLSearchParams(mailParams)
        });
        console.log("Email sent to " + email);
      } catch (mailErr) {
        console.error("Mailgun error (non-fatal):", mailErr.message);
      }
    }

    // Notify admin of every contact/inquiry submission
    if (mailgunDomain && mailgunApiKey && !proofId) {
      fetch("https://api.mailgun.net/v3/" + mailgunDomain + "/messages", {
        method: "POST",
        headers: {
          "Authorization": "Basic " + Buffer.from("api:" + mailgunApiKey).toString("base64"),
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
          from: process.env.MAIL_FROM || "ProofDeed <noreply@" + mailgunDomain + ">",
          to: "info@proofdeed.com",
          subject: "New " + (request_type || "contact") + " submission — " + name + " (" + (resolvedCompany || "no company") + ")",
          text: [
            "New submission on ProofDeed.",
            "",
            "Name: " + name,
            "Email: " + email,
            "Organization: " + (resolvedCompany || "N/A"),
            "Phone: " + (phone || "N/A"),
            "Type: " + (request_type || "contact"),
            "Message: " + (resolvedNotes || "N/A"),
            "",
            "Reply directly to: " + email
          ].join("\n")
        })
      }).catch(err => console.error("Admin notification email failed:", err.message));
    }

    console.log("New " + (request_type || "contact") + " submission from: " + email);
    res.json({ success: true });

  } catch (error) {
    console.error("Contact form error:", error);
    res.status(500).json({ error: "Internal server error." });
  }
});

/* ---------------- API UPGRADE / TOP-UP CHECKOUT ---------------- */
app.post(["/api/v1/upgrade", "/v1/upgrade"], authenticateApiKeyNoLimit, async (req, res) => {
  try {
    const { type } = req.body; // 'topup' | 'upgrade'
    const email = req.apiKey.email;

    const topupPriceId = process.env.PRICE_TOPUP;

    if (type === "topup") {
      if (!topupPriceId) return res.status(500).json({ error: "Top-up not configured." });
      const session = await stripe.checkout.sessions.create({
        mode: "payment",
        payment_method_types: ["card"],
        customer_email: email,
        line_items: [{ price: topupPriceId, quantity: 1 }],
        metadata: { type: "topup_1000", api_key: req.apiKey.api_key },
        success_url: "https://proofdeed.com/api-dashboard?topup=success",
        cancel_url: "https://proofdeed.com/api-dashboard",
      });
      return res.json({ url: session.url });
    }

    // Upgrade — send to pricing/contact
    return res.json({ url: "https://proofdeed.com/contact?vertical=enterprise&upgrade=1" });

  } catch (err) {
    console.error("Upgrade checkout error:", err);
    res.status(500).json({ error: "Internal server error." });
  }
});

/* ---------------- STRIPE CHECKOUT ---------------- */
app.post(["/create-checkout-session", "/api/create-checkout-session"], async (req, res) => {
  try {
    const { plan, success_url, cancel_url, referral } = req.body;

    const subscriptionPlans = {
      "starter-monthly": process.env.PRICE_STARTER_MONTHLY,
      "starter-annual":  process.env.PRICE_STARTER_YEARLY,
      "pro-monthly":     process.env.PRICE_PRO_MONTHLY,
      "pro-annual":      process.env.PRICE_PRO_YEARLY,
      "enterprise":      process.env.PRICE_ENTERPRISE,
    };

    const oneTimePlans = {
      "government-pilot": process.env.PRICE_GOVERNMENT_PILOT,
    };

    const isOneTime = plan in oneTimePlans;
    const priceId = isOneTime ? oneTimePlans[plan] : subscriptionPlans[plan];
    if (!priceId) return res.status(400).json({ error: "Invalid plan: " + plan });

    const session = await stripe.checkout.sessions.create({
      mode: isOneTime ? "payment" : "subscription",
      payment_method_types: isOneTime ? ["card", "us_bank_account"] : ["card"],
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: success_url || "https://proofdeed.com/success",
      cancel_url: cancel_url || "https://proofdeed.com",
      client_reference_id: referral ? referral : undefined,
      metadata: { plan },
    });

    res.json({ url: session.url });

  } catch (err) {
    console.error("Stripe error:", err);
    res.status(500).json({ error: "Internal server error." });
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
    return res.status(400).send("Webhook Error: " + err.message);
  }

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    const email = session.customer_details?.email;
    const customerId = session.customer;
    const subscriptionId = session.subscription;
    const referral = session.client_reference_id;
    const isOneTime = session.mode === "payment";

    console.log("Checkout completed:", email, "mode:", session.mode);

    try {
      // Upsert user record
      await pool.query(
        `INSERT INTO users (email, stripe_customer_id, subscription_id, referred_by, created_at)
         VALUES ($1, $2, $3, $4, NOW())
         ON CONFLICT (email) DO UPDATE
         SET stripe_customer_id = $2, subscription_id = COALESCE($3, users.subscription_id)`,
        [email, customerId, subscriptionId || null, referral || null]
      );

      if (isOneTime && session.metadata?.type === "topup_1000") {
        // Credit top-up — add 1,000 certs and reset notification flags
        const apiKeyVal = session.metadata?.api_key;
        if (apiKeyVal) {
          await pool.query(
            `UPDATE api_keys
             SET monthly_limit = monthly_limit + 1000,
                 notified_80 = FALSE,
                 notified_100 = FALSE
             WHERE api_key = $1`,
            [apiKeyVal]
          );
          console.log("Top-up applied: +1000 certs for key", apiKeyVal);

          // Confirmation email
          const mailgunDomain = process.env.MAILGUN_DOMAIN;
          const mailgunApiKey = process.env.MAILGUN_API_KEY;
          if (email && mailgunDomain && mailgunApiKey) {
            fetch("https://api.mailgun.net/v3/" + mailgunDomain + "/messages", {
              method: "POST",
              headers: {
                "Authorization": "Basic " + Buffer.from("api:" + mailgunApiKey).toString("base64"),
                "Content-Type": "application/x-www-form-urlencoded"
              },
              body: new URLSearchParams({
                from: process.env.MAIL_FROM || "ProofDeed <noreply@" + mailgunDomain + ">",
                to: email,
                subject: "ProofDeed — 1,000 certifications added to your account",
                text: [
                  "Your top-up has been applied.",
                  "",
                  "1,000 additional certifications have been added to your monthly limit.",
                  "Your API is active and ready.",
                  "",
                  "View your updated usage:",
                  "https://proofdeed.com/api-dashboard",
                  "",
                  "ProofDeed\nhttps://proofdeed.com"
                ].join("\n")
              })
            }).catch(err => console.error("Top-up email failed:", err.message));
          }
        }
        return;
      }

      if (isOneTime) {
        // Government pilot — payment received but ACH not yet cleared.
        // Store email + payment_intent ID so we can provision when funds confirm.
        const paymentIntentId = session.payment_intent;
        await pool.query(
          `INSERT INTO api_keys (email, api_key, plan, monthly_limit, used_this_month, active, created_at)
           VALUES ($1, $2, 'government-pilot-pending', 0, 0, FALSE, NOW())
           ON CONFLICT (email) DO UPDATE SET plan = 'government-pilot-pending', active = FALSE`,
          [email, "pending_" + paymentIntentId]
        );
        console.log("Government pilot payment received (pending ACH):", email);

        // Send "payment received" confirmation — key will follow when funds clear
        const mailgunDomain = process.env.MAILGUN_DOMAIN;
        const mailgunApiKey = process.env.MAILGUN_API_KEY;
        if (mailgunDomain && mailgunApiKey) {
          try {
            await fetch("https://api.mailgun.net/v3/" + mailgunDomain + "/messages", {
              method: "POST",
              headers: {
                "Authorization": "Basic " + Buffer.from("api:" + mailgunApiKey).toString("base64"),
                "Content-Type": "application/x-www-form-urlencoded"
              },
              body: new URLSearchParams({
                from: "ProofDeed Government <gov@proofdeed.com>",
                to: email,
                subject: "ProofDeed Government Pilot — Payment Received",
                text: [
                  "Thank you — your payment for the ProofDeed Government Pilot Program has been received.",
                  "",
                  "ACH bank transfers take 3–5 business days to clear. Once your payment is confirmed,",
                  "you will receive a second email with your API key and full access credentials.",
                  "",
                  "Pilot Summary:",
                  "  • Duration: 45 days from activation",
                  "  • Certification limit: 50,000 documents",
                  "  • Access: Upload portal, batch processing, REST API",
                  "  • Fixed fee: $15,000 — no variable costs during pilot",
                  "",
                  "Questions? Contact us at gov@proofdeed.com.",
                  "",
                  "ProofDeed",
                  "https://proofdeed.com"
                ].join("\n")
              })
            });
            console.log("Pilot payment-received email sent to:", email);
          } catch (mailErr) {
            console.error("Pilot payment-received email failed:", mailErr.message);
          }
        }

      } else {
        // Standard subscription — store subscription item ID for metered billing
        let subscriptionItemId = null;
        try {
          const subscription = await stripe.subscriptions.retrieve(subscriptionId);
          subscriptionItemId = subscription.items.data[0]?.id || null;
        } catch (err) {
          console.error("Could not retrieve subscription item:", err.message);
        }

        if (subscriptionItemId) {
          await pool.query(
            `UPDATE api_keys SET stripe_subscription_item_id = $1 WHERE email = $2`,
            [subscriptionItemId, email]
          );
        }
      }

      if (referral) {
        try {
          await pool.query(
            `UPDATE users SET revenue_generated = COALESCE(revenue_generated, 0) + 1 WHERE referral_code = $1`,
            [referral]
          );
          console.log("Referral credited:", referral);
        } catch (err) {
          console.error("Referral update failed:", err.message);
        }
      }

      // Welcome email for new subscribers (not government pilot or top-ups)
      if (!isOneTime && email) {
        const planName = session.metadata?.plan || "starter";
        const planLabel = planName.includes("pro") ? "Professional" : "Starter";
        const certLimit = planName.includes("pro") ? "70" : "25";
        const mailgunDomain = process.env.MAILGUN_DOMAIN;
        const mailgunApiKey = process.env.MAILGUN_API_KEY;
        if (mailgunDomain && mailgunApiKey) {
          fetch("https://api.mailgun.net/v3/" + mailgunDomain + "/messages", {
            method: "POST",
            headers: {
              "Authorization": "Basic " + Buffer.from("api:" + mailgunApiKey).toString("base64"),
              "Content-Type": "application/x-www-form-urlencoded"
            },
            body: new URLSearchParams({
              from: process.env.MAIL_FROM || "ProofDeed <info@proofdeed.com>",
              to: email,
              subject: "Welcome to ProofDeed — your account is active",
              text: [
                "Your ProofDeed " + planLabel + " subscription is now active.",
                "",
                "You have " + certLimit + " certifications per month. Every document you certify receives a permanent, court-admissible proof anchored to the Polygon blockchain.",
                "",
                "Getting started:",
                "  • Certify a document: https://proofdeed.com/upload",
                "  • View your dashboard: https://proofdeed.com/dashboard",
                "  • Verify any certificate: https://proofdeed.com/verify",
                "",
                "Your document is hashed entirely in your browser — we never see or store your files.",
                "",
                "Questions? Reply to this email or contact us at info@proofdeed.com.",
                "",
                "ProofDeed",
                "https://proofdeed.com"
              ].join("\n")
            })
          }).catch(err => console.error("Welcome email failed:", err.message));
        }
      }

    } catch (dbErr) {
      console.error("Webhook DB error:", dbErr.message);
    }
  }

  if (event.type === "customer.subscription.deleted") {
    const subscription = event.data.object;
    const customerId = subscription.customer;
    console.log("Subscription cancelled for customer:", customerId);
    try {
      const userRes = await pool.query(
        `UPDATE users SET subscription_id = NULL WHERE stripe_customer_id = $1 RETURNING email`,
        [customerId]
      );
      if (userRes.rows.length > 0) {
        const email = userRes.rows[0].email;
        await pool.query(
          `UPDATE api_keys SET active = FALSE WHERE email = $1 AND plan NOT IN ('government-pilot', 'government-pilot-pending')`,
          [email]
        );
        console.log("API key deactivated on subscription cancellation for:", email);

        // Win-back email
        const mailgunDomain = process.env.MAILGUN_DOMAIN;
        const mailgunApiKey = process.env.MAILGUN_API_KEY;
        if (mailgunDomain && mailgunApiKey) {
          fetch("https://api.mailgun.net/v3/" + mailgunDomain + "/messages", {
            method: "POST",
            headers: {
              "Authorization": "Basic " + Buffer.from("api:" + mailgunApiKey).toString("base64"),
              "Content-Type": "application/x-www-form-urlencoded"
            },
            body: new URLSearchParams({
              from: process.env.MAIL_FROM || "ProofDeed <info@proofdeed.com>",
              to: email,
              subject: "Your ProofDeed subscription has been cancelled",
              text: [
                "Your ProofDeed subscription has been cancelled and your access has ended.",
                "",
                "Every certificate you created remains permanently on the Polygon blockchain — your proofs are yours forever, regardless of your subscription status.",
                "",
                "If you cancelled by mistake or would like to resubscribe:",
                "  https://proofdeed.com/#pricing",
                "",
                "If there was something we could have done better, we'd genuinely like to know.",
                "Reply to this email — we read every response.",
                "",
                "ProofDeed",
                "https://proofdeed.com"
              ].join("\n")
            })
          }).catch(err => console.error("Win-back email failed:", err.message));
        }
      }
    } catch (dbErr) {
      console.error("Subscription cancellation DB update failed:", dbErr.message);
    }
  }

  if (event.type === "invoice.upcoming") {
    const invoice = event.data.object;
    const email = invoice.customer_email;
    const amountCents = invoice.amount_due || 0;
    const renewalDate = invoice.next_payment_attempt
      ? new Date(invoice.next_payment_attempt * 1000).toLocaleDateString("en-US", { month: "long", day: "numeric", year: "numeric" })
      : "your next billing date";
    const amountFormatted = "$" + (amountCents / 100).toFixed(2);

    const mailgunDomain = process.env.MAILGUN_DOMAIN;
    const mailgunApiKey = process.env.MAILGUN_API_KEY;
    if (mailgunDomain && mailgunApiKey && email) {
      try {
        await fetch("https://api.mailgun.net/v3/" + mailgunDomain + "/messages", {
          method: "POST",
          headers: {
            "Authorization": "Basic " + Buffer.from("api:" + mailgunApiKey).toString("base64"),
            "Content-Type": "application/x-www-form-urlencoded"
          },
          body: new URLSearchParams({
            from: process.env.MAIL_FROM || "ProofDeed <info@proofdeed.com>",
            to: email,
            subject: "Your ProofDeed subscription renews on " + renewalDate,
            text: [
              "Hi,",
              "",
              "This is a reminder that your ProofDeed subscription will automatically renew on " + renewalDate + " for " + amountFormatted + ".",
              "",
              "No action is needed — your access will continue uninterrupted.",
              "",
              "To update your payment method, change your plan, or cancel before you're charged:",
              "  https://proofdeed.com/api-dashboard",
              "",
              "Questions? Reply to this email or contact us at info@proofdeed.com.",
              "",
              "ProofDeed",
              "https://proofdeed.com"
            ].join("\n")
          })
        });
        console.log("Renewal reminder sent to:", email, "for", amountFormatted, "on", renewalDate);
      } catch (mailErr) {
        console.error("Renewal reminder email failed:", mailErr.message);
      }
    }
  }

  if (event.type === "invoice.paid") {
    const invoice = event.data.object;
    const email = invoice.customer_email;
    const amountCents = invoice.amount_paid || 0;
    if (email && amountCents > 0) {
      try {
        await pool.query(
          `UPDATE users SET revenue_generated = COALESCE(revenue_generated, 0) + $1 WHERE email = $2`,
          [amountCents, email]
        );
      } catch (err) {
        console.error("Revenue tracking error:", err.message);
      }
    }
  }

  if (event.type === "invoice.payment_failed") {
    const invoice = event.data.object;
    const customerId = invoice.customer;
    const email = invoice.customer_email;
    console.log("Payment failed for customer:", customerId, email);

    const mailgunDomain = process.env.MAILGUN_DOMAIN;
    const mailgunApiKey = process.env.MAILGUN_API_KEY;
    if (mailgunDomain && mailgunApiKey && email) {
      try {
        await fetch("https://api.mailgun.net/v3/" + mailgunDomain + "/messages", {
          method: "POST",
          headers: {
            "Authorization": "Basic " + Buffer.from("api:" + mailgunApiKey).toString("base64"),
            "Content-Type": "application/x-www-form-urlencoded"
          },
          body: new URLSearchParams({
            from: process.env.MAIL_FROM || "ProofDeed <mailgun@" + mailgunDomain + ">",
            to: email,
            subject: "ProofDeed: Payment failed — action required",
            text: "Hi,\n\nWe were unable to process your ProofDeed subscription payment. Please update your payment method to keep your account active.\n\nUpdate billing: https://proofdeed.com/dashboard\n\nIf you need help, contact us at info@proofdeed.com.\n\nProofDeed\nhttps://proofdeed.com"
          })
        });
      } catch (mailErr) {
        console.error("Payment failed email error (non-fatal):", mailErr.message);
      }
    }
  }

  // Government pilot — provision API key once ACH payment clears
  if (event.type === "payment_intent.succeeded") {
    const paymentIntent = event.data.object;
    const paymentIntentId = paymentIntent.id;

    try {
      // Find a pending pilot record that matches this payment_intent
      const pending = await pool.query(
        `SELECT email FROM api_keys WHERE api_key = $1 AND plan = 'government-pilot-pending'`,
        ["pending_" + paymentIntentId]
      );

      if (pending.rows.length > 0) {
        const email = pending.rows[0].email;
        const pilotKey = "pd_gov_" + require("crypto").randomBytes(24).toString("hex");

        const pilotExpiresAt = new Date(Date.now() + 45 * 24 * 60 * 60 * 1000);
        await pool.query(
          `UPDATE api_keys SET api_key = $1, plan = 'government-pilot', monthly_limit = 50000, active = TRUE, pilot_expires_at = $3
           WHERE email = $2 AND plan = 'government-pilot-pending'`,
          [pilotKey, email, pilotExpiresAt]
        );
        console.log("Government pilot ACH cleared — API key activated for:", email);

        // Send access credentials email
        const mailgunDomain = process.env.MAILGUN_DOMAIN;
        const mailgunApiKey = process.env.MAILGUN_API_KEY;
        if (mailgunDomain && mailgunApiKey) {
          try {
            await fetch("https://api.mailgun.net/v3/" + mailgunDomain + "/messages", {
              method: "POST",
              headers: {
                "Authorization": "Basic " + Buffer.from("api:" + mailgunApiKey).toString("base64"),
                "Content-Type": "application/x-www-form-urlencoded"
              },
              body: new URLSearchParams({
                from: "ProofDeed Government <gov@proofdeed.com>",
                to: email,
                subject: "ProofDeed Government Pilot — Payment Confirmed. Your API Key Is Ready.",
                text: [
                  "Your payment has cleared. Your ProofDeed Government Pilot is now active.",
                  "",
                  "API Key: " + pilotKey,
                  "Pilot Duration: 45 days from today",
                  "Certification Limit: 50,000 documents",
                  "Access: Upload portal, batch processing, and REST API",
                  "",
                  "Getting Started:",
                  "  • Upload portal: https://proofdeed.com/upload",
                  "  • API documentation: https://proofdeed.com/api-docs",
                  "  • Verify a certificate: https://proofdeed.com/verify",
                  "",
                  "API Usage:",
                  "  Include your key in all API requests:",
                  "  Authorization: Bearer " + pilotKey,
                  "",
                  "  Single certification:  POST https://proofdeed.com/api/v1/certify",
                  "  Batch certification:   POST https://proofdeed.com/api/v1/certify/batch",
                  "",
                  "Keep this key secure. To rotate it contact us at info@proofdeed.com.",
                  "",
                  "ProofDeed",
                  "https://proofdeed.com"
                ].join("\n")
              })
            });
            console.log("Pilot activation email sent to:", email);
          } catch (mailErr) {
            console.error("Pilot activation email failed:", mailErr.message);
          }
        }
      }
    } catch (err) {
      console.error("Pilot ACH provisioning error:", err.message);
    }
  }

  res.json({ received: true });
});

/* ---------------- ADMIN DASHBOARD ---------------- */
app.get(["/admin/stats", "/api/admin/stats"], authRateLimit, async (req, res) => {
  try {
    if (!verifyAdminAuth(req)) return res.status(401).json({ error: "Unauthorized." });

    const users = await pool.query(
      `SELECT email, stripe_customer_id, subscription_id, referral_code,
       referred_by, revenue_generated, created_at
       FROM users ORDER BY created_at DESC`
    );

    const certs = await pool.query(`SELECT COUNT(*) as total FROM certifications`);

    const contacts = await pool.query(
      `SELECT name, email, company, notes, request_type, created_at
       FROM contact_submissions ORDER BY created_at DESC`
    );

    const apiKeys = await pool.query(
      `SELECT email, plan, monthly_limit, used_this_month, stripe_subscription_item_id, active, organization_name, created_at
       FROM api_keys ORDER BY created_at DESC`
    );

    res.json({
      users: users.rows,
      totalCertifications: parseInt(certs.rows[0].total),
      contacts: contacts.rows,
      apiKeys: apiKeys.rows
    });

  } catch (error) {
    console.error("Admin stats error:", error);
    res.status(500).json({ error: "Internal server error." });
  }
});

/* ---------------- ADMIN AUTH HELPER ---------------- */
function verifyAdminAuth(req) {
  const adminSecret = req.headers["x-admin-secret"];
  if (adminSecret !== process.env.ADMIN_SECRET) return false;

  // If TOTP is configured, also verify the token
  if (process.env.ADMIN_TOTP_SECRET) {
    const totpToken = req.headers["x-admin-totp"];
    if (!totpToken) return false;
    if (!verifyTOTP(process.env.ADMIN_TOTP_SECRET, totpToken)) return false;
  }

  return true;
}

/* ---------------- COMPLIANCE TOKEN (one-time links) ---------------- */
app.post(["/admin/compliance-token", "/api/admin/compliance-token"], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: "Unauthorized." });
  try {
    const token = crypto.randomBytes(20).toString("hex");
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
    await pool.query(
      `INSERT INTO compliance_tokens (token, expires_at, used, created_at) VALUES ($1, $2, FALSE, NOW())`,
      [token, expiresAt]
    );
    res.json({ url: `https://proofdeed.com/security-compliance?token=${token}` });
  } catch (err) {
    res.status(500).json({ error: "Internal server error." });
  }
});

app.post("/api/compliance-token/validate", async (req, res) => {
  const { token } = req.body;
  if (!token) return res.json({ valid: false, reason: "missing" });
  try {
    const result = await pool.query(`SELECT * FROM compliance_tokens WHERE token = $1`, [token]);
    if (result.rows.length === 0) return res.json({ valid: false, reason: "not_found" });
    const row = result.rows[0];
    if (row.used) return res.json({ valid: false, reason: "used" });
    if (row.expires_at && new Date(row.expires_at) < new Date()) return res.json({ valid: false, reason: "expired" });
    await pool.query(`UPDATE compliance_tokens SET used = TRUE WHERE token = $1`, [token]);
    res.json({ valid: true });
  } catch (err) {
    res.status(500).json({ error: "Internal server error." });
  }
});

/* ---------------- TOTP SETUP (run once) ---------------- */
// Hit this endpoint once with your admin password to get the QR code.
// Scan it with Google Authenticator, then set ADMIN_TOTP_SECRET in DO env vars.
app.get(["/admin/totp-setup", "/api/admin/totp-setup"], authRateLimit, async (req, res) => {
  const adminSecret = req.headers["x-admin-secret"];
  if (adminSecret !== process.env.ADMIN_SECRET) return res.status(401).json({ error: "Unauthorized." });

  if (process.env.ADMIN_TOTP_SECRET) {
    return res.status(400).json({ error: "TOTP already configured. Remove ADMIN_TOTP_SECRET from env to regenerate." });
  }

  const secret = generateTOTPSecret();
  const otpauthUrl = getTOTPUri(secret);
  const qrDataUrl = await QRCode.toDataURL(otpauthUrl);

  res.json({
    secret,
    instructions: "1) Scan the QR code with Google Authenticator. 2) Set ADMIN_TOTP_SECRET=" + secret + " in your DigitalOcean environment variables. 3) Redeploy.",
    qr: qrDataUrl
  });
});

/* ---------------- ADMIN ACTIONS ---------------- */

// Toggle API key active/inactive
app.post(["/admin/api-key/toggle", "/api/admin/api-key/toggle"], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: "Unauthorized." });
  const { email, active } = req.body;
  if (!email || typeof active !== "boolean") return res.status(400).json({ error: "email and active (boolean) required." });
  try {
    await pool.query("UPDATE api_keys SET active = $1 WHERE email = $2", [active, email]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Internal server error." });
  }
});

// Set organization name (white-label) for an API key
app.post(["/admin/api-key/org", "/api/admin/api-key/org"], authRateLimit, async (req, res) => {
  const adminSecret = req.headers["x-admin-secret"];
  if (adminSecret !== process.env.ADMIN_SECRET) return res.status(401).json({ error: "Unauthorized." });
  const { email, organization_name } = req.body;
  if (!email) return res.status(400).json({ error: "email required." });
  try {
    await pool.query("UPDATE api_keys SET organization_name = $1 WHERE email = $2", [organization_name || null, email]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Internal server error." });
  }
});

// Manually set monthly limit for an API key
app.post(["/admin/api-key/limit", "/api/admin/api-key/limit"], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: "Unauthorized." });
  const { email, monthly_limit } = req.body;
  if (!email || typeof monthly_limit !== "number" || monthly_limit < 0) return res.status(400).json({ error: "email and monthly_limit (number) required." });
  try {
    await pool.query("UPDATE api_keys SET monthly_limit = $1 WHERE email = $2", [monthly_limit, email]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Internal server error." });
  }
});

/* ---------------- DB INDEXES ---------------- */
// Run once on startup — safe to re-run (IF NOT EXISTS)
async function ensureIndexes() {
  try {
    // New tables and columns — safe to re-run
    await pool.query(`
      CREATE TABLE IF NOT EXISTS batches (
        id               SERIAL PRIMARY KEY,
        batch_id         TEXT UNIQUE NOT NULL,
        email            TEXT NOT NULL,
        status           TEXT DEFAULT 'processing',
        total            INTEGER DEFAULT 0,
        processed        INTEGER DEFAULT 0,
        failed           INTEGER DEFAULT 0,
        webhook_notified BOOLEAN DEFAULT FALSE,
        created_at       TIMESTAMPTZ DEFAULT NOW()
      );
      ALTER TABLE certifications ADD COLUMN IF NOT EXISTS batch_id TEXT;
      ALTER TABLE certifications ADD COLUMN IF NOT EXISTS label TEXT;
      CREATE TABLE IF NOT EXISTS compliance_tokens (
        id SERIAL PRIMARY KEY,
        token TEXT UNIQUE NOT NULL,
        used BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        expires_at TIMESTAMPTZ
      );
      ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS notified_80 BOOLEAN DEFAULT FALSE;
      ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS notified_100 BOOLEAN DEFAULT FALSE;
      ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS organization_name TEXT;
      ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS pilot_expires_at TIMESTAMPTZ;
      ALTER TABLE certifications ADD COLUMN IF NOT EXISTS api_key_email TEXT;
      ALTER TABLE certifications ADD COLUMN IF NOT EXISTS ip_address TEXT;
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
      CREATE INDEX IF NOT EXISTS idx_certifications_hash ON certifications(hash);
      CREATE INDEX IF NOT EXISTS idx_certifications_user_id ON certifications(user_id);
      CREATE INDEX IF NOT EXISTS idx_certifications_batch_id ON certifications(batch_id);
      CREATE INDEX IF NOT EXISTS idx_api_keys_key ON api_keys(api_key);
      CREATE INDEX IF NOT EXISTS idx_magic_links_token ON magic_links(token);
      CREATE INDEX IF NOT EXISTS idx_batches_batch_id ON batches(batch_id);
    `);
    console.log("DB indexes and schema migrations ensured.");
  } catch (err) {
    console.error("Index creation error (non-fatal):", err.message);
  }
}
ensureIndexes();

/* ---------------- MONTHLY USAGE RESET ---------------- */
// Runs at 00:00 on the 1st of every month (UTC)
cron.schedule("0 0 1 * *", async () => {
  try {
    await pool.query("UPDATE api_keys SET used_this_month = 0");
    console.log("Monthly API key usage reset completed.");
  } catch (err) {
    console.error("Monthly reset error:", err.message);
  }
});

/* ---------------- MAGIC LINK CLEANUP ---------------- */
// Runs daily at 03:00 UTC — purges expired/used tokens older than 1 day
cron.schedule("0 3 * * *", async () => {
  try {
    const result = await pool.query(
      "DELETE FROM magic_links WHERE expires_at < NOW() - INTERVAL '1 day'"
    );
    console.log("Magic link cleanup: removed", result.rowCount, "expired tokens.");
  } catch (err) {
    console.error("Magic link cleanup error:", err.message);
  }
});

/* ---------------- GOVERNMENT PILOT EXPIRY ---------------- */
// Runs daily at 04:00 UTC — deactivates expired pilots and emails them
cron.schedule("0 4 * * *", async () => {
  try {
    const expired = await pool.query(
      `UPDATE api_keys SET active = FALSE
       WHERE plan = 'government-pilot' AND active = TRUE AND pilot_expires_at < NOW()
       RETURNING email`
    );
    for (const row of expired.rows) {
      const mailgunDomain = process.env.MAILGUN_DOMAIN;
      const mailgunApiKey = process.env.MAILGUN_API_KEY;
      if (mailgunDomain && mailgunApiKey) {
        fetch("https://api.mailgun.net/v3/" + mailgunDomain + "/messages", {
          method: "POST",
          headers: {
            "Authorization": "Basic " + Buffer.from("api:" + mailgunApiKey).toString("base64"),
            "Content-Type": "application/x-www-form-urlencoded"
          },
          body: new URLSearchParams({
            from: "ProofDeed Government <gov@proofdeed.com>",
            to: row.email,
            subject: "ProofDeed Government Pilot — Your 45-Day Pilot Has Ended",
            text: [
              "Your ProofDeed Government Pilot Program has now concluded.",
              "",
              "All records certified during your pilot remain permanently on the Polygon blockchain — fully verifiable forever.",
              "",
              "To continue using ProofDeed, please contact us to discuss volume pricing for your agency:",
              "",
              "  Email: gov@proofdeed.com",
              "  Enterprise pricing starts at $0.76/certification, dropping to $0.15 at scale.",
              "",
              "We would love to continue supporting your agency's record integrity needs.",
              "",
              "ProofDeed",
              "https://proofdeed.com"
            ].join("\n")
          })
        }).catch(err => console.error("Pilot expiry email failed:", err.message));
      }
      console.log("Government pilot expired and deactivated:", row.email);
    }
    if (expired.rowCount > 0) console.log("Pilot expiry job: deactivated", expired.rowCount, "pilots.");
  } catch (err) {
    console.error("Pilot expiry job error:", err.message);
  }
});

/* ---------------- API KEY BILLING PORTAL ---------------- */
app.post(["/api/v1/billing-portal", "/v1/billing-portal"], authenticateApiKeyNoLimit, async (req, res) => {
  try {
    const { email } = req.apiKey;
    const userResult = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    const user = userResult.rows[0];
    if (!user || !user.stripe_customer_id) {
      return res.status(404).json({ error: "No billing account found. Contact info@proofdeed.com." });
    }
    const session = await stripe.billingPortal.sessions.create({
      customer: user.stripe_customer_id,
      return_url: "https://proofdeed.com/api-dashboard",
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error("API billing portal error:", err);
    res.status(500).json({ error: "Internal server error." });
  }
});

/* ---------------- DAILY USAGE CHART DATA ---------------- */
app.get(["/api/v1/usage/daily", "/v1/usage/daily"], authenticateApiKey, async (req, res) => {
  try {
    const { email } = req.apiKey;
    const result = await pool.query(
      `SELECT DATE(created_at) as day, COUNT(*) as count
       FROM certifications
       WHERE api_key_email = $1 AND created_at >= NOW() - INTERVAL '30 days'
       GROUP BY DATE(created_at)
       ORDER BY day ASC`,
      [email]
    );
    res.json({ daily: result.rows });
  } catch (err) {
    console.error("Daily usage error:", err);
    res.status(500).json({ error: "Internal server error." });
  }
});

/* ---------------- STRIPE CUSTOMER PORTAL ---------------- */
app.post(["/billing/portal", "/api/billing/portal"], authenticateToken, async (req, res) => {
  try {
    const { email } = req.user;

    const userResult = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    const user = userResult.rows[0];

    if (!user || !user.stripe_customer_id) {
      return res.status(404).json({ error: "No billing account found." });
    }

    const session = await stripe.billingPortal.sessions.create({
      customer: user.stripe_customer_id,
      return_url: "https://proofdeed.com/dashboard",
    });

    res.json({ url: session.url });

  } catch (err) {
    console.error("Portal error:", err);
    res.status(500).json({ error: "Internal server error." });
  }
});

/* ---------------- Unhandled Errors ---------------- */
process.on("unhandledRejection", (reason) => {
  console.error("Unhandled promise rejection:", reason);
});

process.on("uncaughtException", (err) => {
  console.error("Uncaught exception:", err);
  process.exit(1);
});

/* ---------------- Start Server ---------------- */
const server = app.listen(PORT, () => {
  console.log("ProofDeed backend running on port " + PORT);
});

/* ---------------- Graceful Shutdown ---------------- */
async function shutdown(signal) {
  console.log(`${signal} received — shutting down gracefully`);
  server.close(async () => {
    try {
      await pool.end();
      console.log("Database pool closed");
    } catch (err) {
      console.error("Error closing pool:", err.message);
    }
    process.exit(0);
  });

  // Force exit if still hanging after 10s
  setTimeout(() => {
    console.error("Forced shutdown after timeout");
    process.exit(1);
  }, 10000);
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
