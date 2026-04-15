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
// Exclude stripe + resend webhooks from global JSON parsing — they need raw body
app.use((req, res, next) => {
  const raw = ['/api/stripe-webhook', '/stripe-webhook', '/api/webhooks/resend'];
  if (raw.includes(req.originalUrl)) {
    next();
  } else {
    express.json({ limit: "50mb" })(req, res, next);
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

// Demo endpoint rate limit: 5 certifications per IP per hour
const demoRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  keyGenerator: (req) => req.headers['x-forwarded-for']?.split(',')[0] || req.ip,
  message: { success: false, error: "Demo limit reached. Sign up for a free account to continue." }
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

    const { email, monthly_limit, custom_price_per_cert, organization_name, contract_notes } = req.body;
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
      `INSERT INTO api_keys (email, api_key, plan, monthly_limit, used_this_month, stripe_subscription_item_id, organization_name, custom_price_per_cert, contract_notes, active, created_at)
       VALUES ($1, $2, 'enterprise', $3, 0, $4, $5, $6, $7, TRUE, NOW())
       ON CONFLICT (email) DO UPDATE SET api_key = $2, monthly_limit = $3, stripe_subscription_item_id = $4, organization_name = $5, custom_price_per_cert = $6, contract_notes = $7, active = TRUE`,
      [email, apiKey, monthly_limit || 1000, stripeSubscriptionItemId, organization_name || null, custom_price_per_cert || null, contract_notes || null]
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
      organization_name: organization_name || null,
      monthly_limit: monthly_limit || 1000,
      custom_price_per_cert: custom_price_per_cert || null,
      contract_notes: contract_notes || null,
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

  try {
    // Build Merkle tree from all document hashes — one Polygon tx covers entire batch
    const { MerkleTree } = await import("merkletreejs");
    const { default: keccak256 } = await import("keccak256");

    const leaves = certRecords.map(c => keccak256(c.documentHash));
    const tree = new MerkleTree(leaves, keccak256, { sortPairs: true });
    const merkleRoot = tree.getRoot().toString("hex");

    // Single blockchain transaction for the entire batch
    const txHash = await anchorToPolygon(merkleRoot);

    // Update every cert with shared tx + individual Merkle proof
    for (const cert of certRecords) {
      try {
        const leaf = keccak256(cert.documentHash);
        const proof = tree.getProof(leaf).map(p => ({
          data: p.data.toString("hex"),
          position: p.position
        }));
        await pool.query(
          `UPDATE certifications SET polygon_tx = $1, merkle_root = $2, merkle_proof = $3 WHERE certification_id = $4`,
          [txHash, merkleRoot, JSON.stringify(proof), cert.proofId]
        );
        processed++;
      } catch (err) {
        console.error("Merkle proof update failed for", cert.proofId, err.message);
        failed++;
      }
    }

    await pool.query(
      `UPDATE batches SET status = 'completed', processed = $1, failed = $2, merkle_root = $3, polygon_tx = $4 WHERE batch_id = $5`,
      [processed, failed, merkleRoot, txHash, batchId]
    );

  } catch (err) {
    console.error("Batch Merkle anchor failed:", err.message);
    // Fall back to individual anchoring if Merkle fails
    for (const cert of certRecords) {
      try {
        const txHash = await anchorToPolygon(cert.documentHash);
        await pool.query(
          `UPDATE certifications SET polygon_tx = $1 WHERE certification_id = $2`,
          [txHash, cert.proofId]
        );
        processed++;
      } catch (e) {
        console.error("Fallback anchor failed for", cert.proofId, e.message);
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
  }

  if (apiKey.stripe_subscription_item_id && processed > 0) {
    await reportUsageToStripe(apiKey.stripe_subscription_item_id, processed);
  }

  // Fire client webhook if configured
  if (apiKey.webhook_url) {
    const batchResult = await pool.query(
      `SELECT certification_id, hash, polygon_tx, label, merkle_root, merkle_proof, created_at FROM certifications WHERE batch_id = $1`,
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
            merkleRoot: r.merkle_root || null,
            merkleProof: r.merkle_proof || null,
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
    const batchLimit = req.apiKey.plan === 'enterprise' ? 500000 : 1000;
    if (documents.length > batchLimit) {
      return res.status(400).json({ error: `Maximum ${batchLimit.toLocaleString()} documents per batch.` });
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
      `SELECT certification_id, hash, polygon_tx, label, merkle_root, merkle_proof, created_at FROM certifications WHERE batch_id = $1`,
      [batchId]
    );
    res.json({
      batchId: b.batch_id,
      status: b.status,
      total: b.total,
      processed: b.processed,
      failed: b.failed,
      merkleRoot: b.merkle_root || null,
      polygonTx: b.polygon_tx || null,
      webhookNotified: b.webhook_notified,
      createdAt: b.created_at,
      results: certs.rows.map(r => ({
        proofId: r.certification_id,
        documentHash: r.hash,
        label: r.label,
        polygon_tx: r.polygon_tx,
        merkleRoot: r.merkle_root || null,
        merkleProof: r.merkle_proof || null,
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
/* ---------------- PUBLIC DEMO CERTIFY ---------------- */
app.post(["/api/demo/certify", "/demo/certify"], demoRateLimit, async (req, res) => {
  try {
    const { hash, fileName } = req.body;
    if (!hash || typeof hash !== 'string' || !/^[a-f0-9]{64}$/.test(hash)) {
      return res.status(400).json({ success: false, error: "Valid SHA-256 hash required." });
    }

    const proofId = "PD-" + Date.now();
    const timestamp = new Date().toISOString();
    const documentData = { fileName: fileName || 'document', demo: true };

    await pool.query(
      `INSERT INTO certifications (certification_id, hash, polygon_tx, api_key_email, created_at, document_data)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (certification_id) DO NOTHING`,
      [proofId, hash, null, 'demo@proofdeed.com', timestamp, JSON.stringify(documentData)]
    );

    res.json({
      success: true,
      proofId,
      hash,
      timestamp,
      polygon_tx: null,
      verifyUrl: `https://proofdeed.com/verify/${proofId}`
    });
  } catch (error) {
    console.error("Demo certify error:", error);
    res.status(500).json({ success: false, error: "Certification failed." });
  }
});

app.get(["/verify/:certId", "/api/verify/:certId"], async (req, res) => {
  try {
    const { certId } = req.params;

    if (!certId) {
      return res.status(400).json({ success: false, error: "Certificate ID required." });
    }

    // Demo certificate — always returns a live-looking result for the /demo page
    if (certId === 'PD-1774689084') {
      return res.json({
        success: true,
        certification: {
          certification_id: 'PD-1774689084',
          hash: 'a3f8d2c1e9b047563f2a1d8e4c7b09f23a1e5d7c8b2f4609e3a7d1c5b8f2e4a9',
          polygon_tx: '0x29bfe7c1d3a8f042e91bc7354d2a80f5e6c1d398',
          created_at: '2026-04-09T10:42:18.000Z',
          document_data: { fileName: 'Executed_Purchase_Agreement_v3.pdf' },
          is_demo: true
        }
      });
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

    if (request_type === "purchase_order" && mailgunDomain && mailgunApiKey) {
      // Notify admin
      await fetch("https://api.mailgun.net/v3/" + mailgunDomain + "/messages", {
        method: "POST",
        headers: {
          "Authorization": "Basic " + Buffer.from("api:" + mailgunApiKey).toString("base64"),
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
          from: process.env.MAIL_FROM || "ProofDeed <mailgun@" + mailgunDomain + ">",
          to: process.env.MAIL_TO || process.env.ADMIN_EMAIL || "gov@proofdeed.com",
          subject: "🏛 PO Request: $15K Pilot — " + (resolvedCompany || name),
          text: "Purchase Order request received.\n\nName: " + name + "\nAgency: " + (resolvedCompany || "N/A") + "\nEmail: " + email + "\nMessage: " + (resolvedNotes || "N/A") + "\n\nAction required: Send invoice to " + email + "\n\nProofDeed Admin\nhttps://proofdeed.com/admin"
        })
      }).catch(() => {});

      // Confirm to prospect
      await fetch("https://api.mailgun.net/v3/" + mailgunDomain + "/messages", {
        method: "POST",
        headers: {
          "Authorization": "Basic " + Buffer.from("api:" + mailgunApiKey).toString("base64"),
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
          from: process.env.MAIL_FROM || "ProofDeed <mailgun@" + mailgunDomain + ">",
          to: email,
          subject: "ProofDeed — Government Pilot Invoice Request Received",
          text: "Hi " + name + ",\n\nWe received your request for the ProofDeed Government Pilot Program ($15,000).\n\nWe will send a formal invoice to this email within 1 business day. Net 30 terms are available for government agencies.\n\nOnce payment is confirmed, your API key and onboarding materials will be sent immediately.\n\nIf you have any questions, reply to this email or contact us at gov@proofdeed.com.\n\nProofDeed\nhttps://proofdeed.com"
        })
      }).catch(() => {});

      console.log("Purchase order request received from:", email, resolvedCompany);
      return res.json({ success: true });
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

    const sessionParams = {
      mode: isOneTime ? "payment" : "subscription",
      payment_method_types: isOneTime ? ["card", "us_bank_account"] : ["card"],
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: success_url || "https://proofdeed.com/success",
      cancel_url: cancel_url || "https://proofdeed.com",
      client_reference_id: referral ? referral : undefined,
      metadata: { plan },
    };

    if (isOneTime) {
      sessionParams.payment_method_options = {
        us_bank_account: {
          financial_connections: { permissions: ["payment_method"] },
          verification_method: "instant",
        },
      };
    }

    const session = await stripe.checkout.sessions.create(sessionParams);

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

    const TEST_EMAILS = ['sjjk@pm.me'];
    const users = await pool.query(
      `SELECT email, stripe_customer_id, subscription_id, referral_code,
       referred_by, revenue_generated, created_at
       FROM users WHERE email != ALL($1) ORDER BY created_at DESC`,
      [TEST_EMAILS]
    );

    const testUserIds = await pool.query(
      `SELECT id FROM users WHERE email = ANY($1)`, [TEST_EMAILS]
    );
    const testIds = testUserIds.rows.map(r => r.id);
    const certs = testIds.length > 0
      ? await pool.query(
          `SELECT COUNT(*) as total FROM certifications WHERE user_id != ALL($1) OR user_id IS NULL`,
          [testIds]
        )
      : await pool.query(`SELECT COUNT(*) as total FROM certifications`);

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
/* ---------------- ADMIN: REVENUE ---------------- */
app.get(["/admin/revenue", "/api/admin/revenue"], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: "Unauthorized." });
  try {
    // Pull active subscriptions from Stripe for real MRR
    const subscriptions = await stripe.subscriptions.list({ status: 'active', limit: 100, expand: ['data.plan'] });
    let mrr = 0;
    const plans = {};
    for (const sub of subscriptions.data) {
      const amt = (sub.items.data[0]?.price?.unit_amount || 0) / 100;
      const interval = sub.items.data[0]?.price?.recurring?.interval;
      const monthly = interval === 'year' ? amt / 12 : amt;
      mrr += monthly;
      const nickname = sub.items.data[0]?.price?.nickname || sub.items.data[0]?.price?.id || 'Unknown';
      plans[nickname] = (plans[nickname] || 0) + 1;
    }

    // Recent charges
    const charges = await stripe.charges.list({ limit: 20 });
    const recentPayments = charges.data.filter(c => c.paid).map(c => ({
      amount: c.amount / 100,
      email: c.billing_details?.email || c.receipt_email || '—',
      date: new Date(c.created * 1000).toISOString(),
      description: c.description || 'Payment',
    }));

    // Cert volume by day (last 30 days)
    const certsByDay = await pool.query(`
      SELECT DATE(created_at) as day, COUNT(*) as count
      FROM certifications
      WHERE created_at > NOW() - INTERVAL '30 days'
      GROUP BY day ORDER BY day ASC
    `);

    // Demo cert count
    const demoCerts = await pool.query(`SELECT COUNT(*) as total FROM certifications WHERE document_data::text LIKE '%"demo":true%'`);

    res.json({
      mrr: Math.round(mrr * 100) / 100,
      arr: Math.round(mrr * 12 * 100) / 100,
      activeSubscriptions: subscriptions.data.length,
      planBreakdown: plans,
      recentPayments,
      certsByDay: certsByDay.rows,
      demoCertifications: parseInt(demoCerts.rows[0].total),
    });
  } catch (error) {
    console.error("Admin revenue error:", error.message, error.type, error.code);
    res.status(500).json({ error: "Failed to load revenue data.", detail: error.message });
  }
});

/* ---------------- ADMIN: OUTREACH CRM ---------------- */
app.get(["/admin/outreach", "/api/admin/outreach"], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: "Unauthorized." });
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS outreach_contacts (
        id SERIAL PRIMARY KEY, name TEXT NOT NULL, email TEXT, company TEXT,
        title TEXT, industry TEXT, county TEXT, state TEXT,
        status TEXT DEFAULT 'sent', notes TEXT,
        first_sent_at TIMESTAMPTZ, last_contact_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    const result = await pool.query(`SELECT * FROM outreach_contacts ORDER BY last_contact_at DESC NULLS LAST, created_at DESC`);
    res.json({ contacts: result.rows });
  } catch (error) {
    console.error("Outreach CRM error:", error);
    res.status(500).json({ error: "Failed to load outreach contacts." });
  }
});

app.post(["/admin/outreach/import", "/api/admin/outreach/import"], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: "Unauthorized." });
  try {
    const { contacts } = req.body;
    if (!Array.isArray(contacts)) return res.status(400).json({ error: "contacts array required." });
    let imported = 0;
    for (const c of contacts) {
      await pool.query(`
        INSERT INTO outreach_contacts (name, email, company, title, industry, county, state, status, first_sent_at, last_contact_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,'sent', NOW(), NOW())
        ON CONFLICT DO NOTHING
      `, [c.name||'', c.email||'', c.company||'', c.title||'', c.industry||'government', c.county||'', c.state||'']);
      imported++;
    }
    res.json({ success: true, imported });
  } catch (error) {
    res.status(500).json({ error: "Import failed." });
  }
});

app.post(["/admin/outreach/update", "/api/admin/outreach/update"], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: "Unauthorized." });
  try {
    const { id, status, notes } = req.body;
    await pool.query(`
      UPDATE outreach_contacts SET status=$1, notes=$2, last_contact_at=NOW() WHERE id=$3
    `, [status, notes, id]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: "Update failed." });
  }
});

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
      ALTER TABLE certifications ADD COLUMN IF NOT EXISTS merkle_root TEXT;
      ALTER TABLE certifications ADD COLUMN IF NOT EXISTS merkle_proof JSONB;
      ALTER TABLE batches ADD COLUMN IF NOT EXISTS merkle_root TEXT;
      ALTER TABLE batches ADD COLUMN IF NOT EXISTS polygon_tx TEXT;
      ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS custom_price_per_cert NUMERIC(10,4);
      ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS contract_notes TEXT;
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

      -- Outreach CRM table + new columns
      CREATE TABLE IF NOT EXISTS outreach_contacts (
        id              SERIAL PRIMARY KEY,
        name            TEXT NOT NULL,
        email           TEXT UNIQUE NOT NULL,
        company         TEXT,
        title           TEXT,
        industry        TEXT,
        county          TEXT,
        state           TEXT,
        status          TEXT DEFAULT 'pending',
        notes           TEXT,
        first_sent_at   TIMESTAMPTZ,
        last_contact_at TIMESTAMPTZ,
        created_at      TIMESTAMPTZ DEFAULT NOW()
      );
      ALTER TABLE outreach_contacts ADD COLUMN IF NOT EXISTS reply_to_tag TEXT UNIQUE;
      ALTER TABLE outreach_contacts ADD COLUMN IF NOT EXISTS resend_message_id TEXT;
      ALTER TABLE outreach_contacts ADD COLUMN IF NOT EXISTS opened_count INTEGER DEFAULT 0;
      ALTER TABLE outreach_contacts ADD COLUMN IF NOT EXISTS tier TEXT DEFAULT 'primary';
      ALTER TABLE outreach_contacts ADD COLUMN IF NOT EXISTS priority_score INTEGER DEFAULT 0;
      ALTER TABLE outreach_contacts ADD COLUMN IF NOT EXISTS pipeline_stage TEXT DEFAULT 'contacted';
      ALTER TABLE outreach_contacts ADD COLUMN IF NOT EXISTS pain_status TEXT DEFAULT 'unaware';
      ALTER TABLE outreach_contacts ADD COLUMN IF NOT EXISTS use_case TEXT;

      -- Outreach events log
      CREATE TABLE IF NOT EXISTS outreach_events (
        id              SERIAL PRIMARY KEY,
        contact_id      INTEGER REFERENCES outreach_contacts(id) ON DELETE CASCADE,
        event_type      TEXT NOT NULL,
        event_source    TEXT DEFAULT 'resend',
        resend_event_id TEXT UNIQUE,
        metadata        JSONB,
        occurred_at     TIMESTAMPTZ DEFAULT NOW(),
        created_at      TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS lead_engine_state (
        key        TEXT PRIMARY KEY,
        value      TEXT,
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );

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

/* ================================================================
   OUTREACH AUTOMATION — WEBHOOKS + ADMIN CRM API
   ================================================================ */

// Status priority — higher index wins, except 'replied' always wins
const STATUS_PRIORITY = ['pending','sent','delivered','opened','clicked','replied','bounced','complained','unsubscribed'];
function statusBeats(incoming, current) {
  if (incoming === 'replied') return true;
  if (['bounced','complained','unsubscribed'].includes(current)) return false;
  return STATUS_PRIORITY.indexOf(incoming) > STATUS_PRIORITY.indexOf(current);
}

// ---------- Resend OUTBOUND webhook (opened/clicked/bounced/delivered) ----------
app.post(['/api/webhooks/resend', '/webhooks/resend'], express.raw({ type: '*/*' }), async (req, res) => {
  res.status(200).json({ received: true }); // always ack immediately

  try {
    let event;
    // Verify signature if secret is configured
    if (process.env.RESEND_WEBHOOK_SECRET) {
      try {
        const { Webhook } = await import('svix');
        const wh = new Webhook(process.env.RESEND_WEBHOOK_SECRET);
        event = wh.verify(req.body, req.headers);
      } catch { return; }
    } else {
      event = JSON.parse(req.body.toString());
    }

    const typeMap = {
      'email.delivered':  'delivered',
      'email.opened':     'opened',
      'email.clicked':    'clicked',
      'email.bounced':    'bounced',
      'email.complained': 'complained',
    };
    const newStatus = typeMap[event.type];
    if (!newStatus) return;

    const data = event.data || {};
    const tags = Array.isArray(data.tags) ? data.tags : [];
    const contactIdTag = tags.find((t) => t.name === 'contact_id');

    let contact = null;
    if (contactIdTag) {
      const r = await pool.query('SELECT * FROM outreach_contacts WHERE id=$1', [contactIdTag.value]);
      contact = r.rows[0];
    }
    if (!contact && data.email_id) {
      const r = await pool.query('SELECT * FROM outreach_contacts WHERE resend_message_id=$1', [data.email_id]);
      contact = r.rows[0];
    }
    if (!contact) return;

    const eventId = data.email_id ? `${data.email_id}:${event.type}` : null;
    const metadata = {
      email_id: data.email_id,
      to: data.to,
      link: data.click?.link,
      bounce_type: data.bounce?.type,
      bounce_message: data.bounce?.message,
      ip_address: data.ip_address,
      user_agent: data.user_agent,
    };

    await pool.query(`
      INSERT INTO outreach_events (contact_id, event_type, event_source, resend_event_id, metadata, occurred_at)
      VALUES ($1,$2,'resend',$3,$4,NOW())
      ON CONFLICT (resend_event_id) DO NOTHING
    `, [contact.id, newStatus, eventId, JSON.stringify(metadata)]);

    if (statusBeats(newStatus, contact.status)) {
      const extra = newStatus === 'opened' ? ', opened_count = COALESCE(opened_count,0) + 1' : '';
      await pool.query(`
        UPDATE outreach_contacts SET status=$1, last_contact_at=NOW()${extra} WHERE id=$2
      `, [newStatus, contact.id]);
    }
  } catch (err) {
    console.error('Resend webhook error:', err.message);
  }
});

// ---------- Resend INBOUND webhook (reply detection) ----------
app.post(['/api/webhooks/resend-inbound', '/webhooks/resend-inbound'], async (req, res) => {
  res.status(200).json({ received: true });
  try {
    if (process.env.RESEND_INBOUND_SECRET && req.query.secret !== process.env.RESEND_INBOUND_SECRET) return;

    const body = req.body || {};
    const toField = body.to || body.To || '';
    const match = toField.match(/reply\+([^@\s<>]+)@send\.proofdeed\.com/i);
    if (!match) return;

    const tag = match[1];
    const r = await pool.query('SELECT * FROM outreach_contacts WHERE reply_to_tag=$1', [tag]);
    const contact = r.rows[0];
    if (!contact) return;

    const fromField = body.from || body.From || '';
    const subject = body.subject || body.Subject || '';
    const textSnippet = (body.text || body.Text || '').substring(0, 500);

    await pool.query(`
      INSERT INTO outreach_events (contact_id, event_type, event_source, metadata, occurred_at)
      VALUES ($1,'replied','inbound',$2,NOW())
    `, [contact.id, JSON.stringify({ from: fromField, subject, snippet: textSnippet })]);

    // Detect high intent in reply
    const replyText = (subject + ' ' + textSnippet).toLowerCase();
    const highIntentKeywords = ['interested', 'interest', 'learn more', 'tell me more', 'details', 'schedule', 'call', 'demo', 'pricing', 'pilot', 'how does', 'sounds good', 'let\'s talk', 'set up'];
    const isHighIntent = highIntentKeywords.some(k => replyText.includes(k));

    const newPipelineStage = isHighIntent ? 'pilot_discussed' : 'replied';
    const newPainStatus = isHighIntent ? 'active' : 'aware';

    await pool.query(`
      UPDATE outreach_contacts
      SET status='replied', pipeline_stage=$1, pain_status=$2, last_contact_at=NOW()
      WHERE id=$3
    `, [newPipelineStage, newPainStatus, contact.id]);

    console.log(`✅ Reply detected from ${fromField} → contact #${contact.id} (${contact.name}) — intent: ${isHighIntent ? 'HIGH 🔥' : 'standard'}`);

    // Alert on high-intent reply
    if (isHighIntent) {
      const mailgunDomain = process.env.MAILGUN_DOMAIN;
      const mailgunApiKey = process.env.MAILGUN_API_KEY;
      if (mailgunDomain && mailgunApiKey) {
        fetch('https://api.mailgun.net/v3/' + mailgunDomain + '/messages', {
          method: 'POST',
          headers: {
            'Authorization': 'Basic ' + Buffer.from('api:' + mailgunApiKey).toString('base64'),
            'Content-Type': 'application/x-www-form-urlencoded'
          },
          body: new URLSearchParams({
            from: process.env.MAIL_FROM || 'ProofDeed <mailgun@' + mailgunDomain + '>',
            to: process.env.MAIL_TO || 'info@proofdeed.com',
            subject: `🔥 HOT REPLY: ${contact.name} (${contact.company}) — Move to Pilot Discussion`,
            text: `High-intent reply detected!\n\nContact: ${contact.name}\nCompany: ${contact.company}\nEmail: ${contact.email}\nTitle: ${contact.title || 'N/A'}\nIndustry: ${contact.industry}\nPriority Score: ${contact.priority_score || 'N/A'}\n\nTheir reply subject: ${subject}\nSnippet: ${textSnippet}\n\nAction: Move to Pilot Discussed — reach out within 24 hours.\n\nAdmin: https://proofdeed.com/admin`
          })
        }).catch(() => {});
      }
    }
  } catch (err) {
    console.error('Inbound webhook error:', err.message);
  }
});

// ---------- Admin: Outreach Stats ----------
app.get(['/api/admin/outreach/stats', '/admin/outreach/stats'], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: 'Unauthorized.' });
  try {
    const statusCounts = await pool.query(`SELECT status, COUNT(*) as count FROM outreach_contacts GROUP BY status`);
    const totalEvents = await pool.query(`SELECT COUNT(*) as total FROM outreach_events WHERE occurred_at > NOW() - INTERVAL '24 hours'`);
    const totalContacts = await pool.query(`SELECT COUNT(*) as total FROM outreach_contacts`);
    res.json({
      byStatus: statusCounts.rows.reduce((acc, r) => { acc[r.status] = parseInt(r.count); return acc; }, {}),
      eventsToday: parseInt(totalEvents.rows[0].total),
      totalContacts: parseInt(totalContacts.rows[0].total),
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ---------- Admin: Outreach Activity Feed ----------
app.get(['/api/admin/outreach/feed', '/admin/outreach/feed'], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: 'Unauthorized.' });
  try {
    const result = await pool.query(`
      SELECT e.id, e.event_type, e.occurred_at, e.metadata,
             c.id as contact_id, c.name, c.email, c.company, c.industry, c.status
      FROM outreach_events e
      JOIN outreach_contacts c ON c.id = e.contact_id
      ORDER BY e.occurred_at DESC
      LIMIT 50
    `);
    res.json({ events: result.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ---------- Admin: Outreach Contacts (paginated, searchable) ----------
app.get(['/api/admin/outreach/contacts', '/admin/outreach/contacts'], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: 'Unauthorized.' });
  try {
    const search = req.query.search ? `%${req.query.search}%` : '%';
    const status = req.query.status || '';
    const industry = req.query.industry || '';
    const hotOnly = req.query.hot === '1';
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(200, parseInt(req.query.limit) || 50);
    const offset = (page - 1) * limit;

    const conditions = ['(name ILIKE $1 OR email ILIKE $1 OR company ILIKE $1)'];
    const params = [search];
    if (status) { params.push(status); conditions.push(`status=$${params.length}`); }
    if (industry) { params.push(industry); conditions.push(`industry=$${params.length}`); }
    if (hotOnly) conditions.push(`priority_score >= 7`);

    const whereClause = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

    const result = await pool.query(`
      SELECT * FROM outreach_contacts
      ${whereClause}
      ORDER BY
        COALESCE(priority_score, 0) DESC,
        CASE status WHEN 'replied' THEN 0 WHEN 'in_talks' THEN 1 WHEN 'clicked' THEN 2
          WHEN 'opened' THEN 3 WHEN 'delivered' THEN 4 ELSE 5 END,
        last_contact_at DESC NULLS LAST
      LIMIT $${params.length + 1} OFFSET $${params.length + 2}
    `, [...params, limit, offset]);

    const countResult = await pool.query(`
      SELECT COUNT(*) as total FROM outreach_contacts ${whereClause}
    `, params);

    res.json({ contacts: result.rows, total: parseInt(countResult.rows[0].total), page, limit });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ---------- Admin: Contact Timeline ----------
app.get(['/api/admin/outreach/contacts/:id/timeline', '/admin/outreach/contacts/:id/timeline'], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: 'Unauthorized.' });
  try {
    const contact = await pool.query('SELECT * FROM outreach_contacts WHERE id=$1', [req.params.id]);
    if (!contact.rows[0]) return res.status(404).json({ error: 'Not found.' });
    const events = await pool.query(`
      SELECT * FROM outreach_events WHERE contact_id=$1 ORDER BY occurred_at ASC
    `, [req.params.id]);
    res.json({ contact: contact.rows[0], events: events.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ---------- Admin: Update Contact ----------
app.put(['/api/admin/outreach/contacts/:id', '/admin/outreach/contacts/:id'], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: 'Unauthorized.' });
  try {
    const { status, notes, pipeline_stage, pain_status } = req.body;
    await pool.query(`
      UPDATE outreach_contacts
      SET status=COALESCE($1,status), notes=COALESCE($2,notes),
          pipeline_stage=COALESCE($3,pipeline_stage), pain_status=COALESCE($4,pain_status),
          last_contact_at=NOW()
      WHERE id=$5
    `, [status, notes, pipeline_stage, pain_status, req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ---------------- Lead Engine ---------------- */
const LEAD_TARGETS = [
  // ── TIER 1: Primary Buyers — Recorder/Clerk roles (fastest path to revenue)
  { industry: 'government', role: 'recorder', tier: 'primary',    title: 'County Recorder',              query: '"County Recorder" contact email county USA site:*.gov OR site:*.us 2024 2025' },
  { industry: 'government', role: 'recorder', tier: 'primary',    title: 'Register of Deeds',            query: '"Register of Deeds" contact email county USA site:*.gov' },
  { industry: 'government', role: 'recorder', tier: 'primary',    title: 'Clerk of Court',               query: '"Clerk of Court" civil records contact email county USA site:*.gov' },
  { industry: 'government', role: 'recorder', tier: 'primary',    title: 'Chief Deputy Recorder',        query: '"Chief Deputy Recorder" OR "Deputy County Clerk" contact email county USA' },
  { industry: 'government', role: 'recorder', tier: 'primary',    title: 'Land Records Manager',         query: '"Land Records Manager" OR "Land Records Supervisor" county USA contact email' },
  { industry: 'government', role: 'recorder', tier: 'primary',    title: 'Recording Operations Manager', query: '"Recording Operations" manager county government USA contact email' },

  // ── TIER 2: Influencers — Legal/Risk/Audit (help justify the buy)
  { industry: 'government', role: 'legal',    tier: 'influencer', title: 'County Attorney',              query: '"County Attorney" OR "County Counsel" government USA contact email site:*.gov' },
  { industry: 'government', role: 'legal',    tier: 'influencer', title: 'City Attorney',                query: '"City Attorney" municipal legal department USA contact email site:*.gov' },
  { industry: 'government', role: 'risk',     tier: 'influencer', title: 'Risk Management Director',     query: '"Risk Management Director" county OR city government USA contact email' },
  { industry: 'government', role: 'risk',     tier: 'influencer', title: 'Compliance Officer',           query: '"Compliance Officer" county OR city government USA contact email' },
  { industry: 'government', role: 'risk',     tier: 'influencer', title: 'Internal Audit Director',      query: '"Internal Audit Director" OR "Chief Auditor" county government USA contact' },

  // ── TIER 3: Approvers — IT/Tech (gatekeepers)
  { industry: 'government', role: 'it',       tier: 'approver',   title: 'County CIO',                   query: '"County CIO" OR "County IT Director" government USA contact email' },
  { industry: 'government', role: 'it',       tier: 'approver',   title: 'Director of Digital Services',  query: '"Director of Digital Services" OR "Director of Innovation" county city USA' },
  { industry: 'government', role: 'it',       tier: 'approver',   title: 'Enterprise Applications Manager', query: '"Enterprise Applications Manager" county government USA contact email' },

  // ── TIER 4: Expansion buyers (after initial traction)
  { industry: 'government', role: 'procurement', tier: 'expansion', title: 'Procurement Director',       query: '"Procurement Director" OR "Purchasing Manager" county government USA contact' },
  { industry: 'government', role: 'expansion',   tier: 'expansion', title: 'Housing Authority Director', query: '"Housing Authority" director executive USA contact email 2024 2025' },
  { industry: 'government', role: 'expansion',   tier: 'expansion', title: 'Tax Assessor',               query: '"Tax Assessor" OR "County Treasurer" foreclosure records USA contact email' },
  { industry: 'government', role: 'expansion',   tier: 'expansion', title: 'Land Bank Director',         query: '"Land Bank" director OR "Redevelopment Authority" USA contact email' },
  { industry: 'government', role: 'expansion',   tier: 'expansion', title: 'Public Records Officer',     query: '"Public Records Officer" OR "FOIA Officer" county government USA contact email' },
  { industry: 'government', role: 'expansion',   tier: 'expansion', title: 'State Records Manager',      query: '"State Records Management" director OR manager USA contact email site:*.gov' },

  // ════════════════════════════════════════════════════════
  // AUTOMOTIVE — proof of ownership + transaction integrity
  // ════════════════════════════════════════════════════════

  // ── TIER 1: Core Buyers — title, compliance, F&I
  { industry: 'auto', role: 'dealer',     tier: 'primary',    title: 'F&I Director',                  query: '"Finance and Insurance Director" OR "F&I Director" dealership automotive USA contact email' },
  { industry: 'auto', role: 'dealer',     tier: 'primary',    title: 'Title Manager',                  query: '"Title Manager" OR "Title Clerk" automotive dealership USA contact email' },
  { industry: 'auto', role: 'dealer',     tier: 'primary',    title: 'Dealer Compliance Manager',      query: '"Dealer Compliance Manager" OR "Compliance Director" automotive dealership USA contact' },
  { industry: 'auto', role: 'dealer',     tier: 'primary',    title: 'Used Car Manager',               query: '"Used Car Manager" OR "Pre-Owned Manager" dealership USA contact email' },
  { industry: 'auto', role: 'dealer',     tier: 'primary',    title: 'General Manager',                query: '"General Manager" automotive dealership "title" OR "compliance" USA contact email' },

  // ── TIER 2: High-Volume Operators
  { industry: 'auto', role: 'auction',    tier: 'influencer', title: 'Auto Auction Operations Director', query: '"Auto Auction" operations director Manheim ADESA USA contact email executive' },
  { industry: 'auto', role: 'auction',    tier: 'influencer', title: 'Vehicle Remarketing Manager',    query: '"Vehicle Remarketing Manager" OR "Remarketing Director" automotive USA contact' },
  { industry: 'auto', role: 'fleet',      tier: 'influencer', title: 'Fleet Management Director',      query: '"Fleet Management Director" OR "Fleet Operations Director" USA contact email' },
  { industry: 'auto', role: 'fleet',      tier: 'influencer', title: 'Rental Car Operations Manager',  query: '"Rental Car Operations" manager Enterprise Hertz Avis USA contact email' },

  // ── TIER 3: Lenders & Title Risk
  { industry: 'auto', role: 'lender',     tier: 'approver',   title: 'Auto Lending Director',          query: '"Auto Lending Director" OR "Auto Finance Director" bank "credit union" USA contact' },
  { industry: 'auto', role: 'lender',     tier: 'approver',   title: 'Collateral Risk Manager',        query: '"Collateral Risk Manager" automotive lender bank USA contact email' },
  { industry: 'auto', role: 'lender',     tier: 'approver',   title: 'Lien Release Manager',           query: '"Lien Release Manager" auto lender bank USA contact email' },
  { industry: 'auto', role: 'lender',     tier: 'approver',   title: 'Loan Servicing Director',        query: '"Loan Servicing Director" auto lender USA contact email executive' },

  // ── TIER 4: Digital Platform Players
  { industry: 'auto', role: 'digital',    tier: 'expansion',  title: 'VP of Operations (Online Auto)', query: '"VP of Operations" Carvana OR Vroom OR CarMax OR "online auto" USA contact email' },
  { industry: 'auto', role: 'digital',    tier: 'expansion',  title: 'Title & Registration Ops Lead',  query: '"Title and Registration" operations lead "digital dealer" OR "online dealer" USA contact' },
  { industry: 'auto', role: 'digital',    tier: 'expansion',  title: 'Marketplace Compliance Lead',    query: '"Marketplace Compliance" automotive platform USA contact email executive' },

  // ── TIER 5: Extended Buyers
  { industry: 'auto', role: 'insurance',  tier: 'expansion',  title: 'Auto Insurance Claims Director', query: '"Insurance Claims Director" auto claims "document" OR "total loss" USA contact email' },
  { industry: 'auto', role: 'insurance',  tier: 'expansion',  title: 'Salvage & Total Loss Manager',   query: '"Total Loss Manager" OR "Salvage Manager" auto insurance USA contact email' },

  // ════════════════════════════════════════════════════════
  // INSTITUTIONAL — audit-proof document integrity
  // ════════════════════════════════════════════════════════

  // ── TIER 1: Core Buyers — compliance + records
  { industry: 'institutional', role: 'compliance', tier: 'primary',    title: 'Chief Compliance Officer',     query: '"Chief Compliance Officer" "document management" OR "records" USA corporation contact email' },
  { industry: 'institutional', role: 'compliance', tier: 'primary',    title: 'Director of Records Management', query: '"Director of Records Management" OR "Records Management Director" USA institution contact' },
  { industry: 'institutional', role: 'compliance', tier: 'primary',    title: 'Document Control Manager',     query: '"Document Control Manager" institution OR corporation USA contact email' },
  { industry: 'institutional', role: 'compliance', tier: 'primary',    title: 'Head of Governance / GRC',     query: '"Head of Governance" OR "GRC Director" OR "Governance Risk Compliance" USA contact email' },
  { industry: 'institutional', role: 'compliance', tier: 'primary',    title: 'Internal Audit Director',      query: '"Internal Audit Director" OR "Chief Auditor" corporation USA contact email' },
  { industry: 'institutional', role: 'compliance', tier: 'primary',    title: 'Legal Operations Director',    query: '"Legal Operations Director" OR "Director of Legal Operations" USA corporation contact' },

  // ── TIER 2: Legal & Risk
  { industry: 'institutional', role: 'legal',      tier: 'influencer', title: 'General Counsel',              query: '"General Counsel" OR "Deputy General Counsel" corporation USA "document" contact email' },
  { industry: 'institutional', role: 'legal',      tier: 'influencer', title: 'Litigation Support Manager',   query: '"Litigation Support Manager" corporation OR "law firm" USA contact email' },
  { industry: 'institutional', role: 'legal',      tier: 'influencer', title: 'Contract Management Director', query: '"Contract Management Director" OR "Director of Contracts" USA corporation contact email' },
  { industry: 'institutional', role: 'risk',       tier: 'influencer', title: 'Risk Management Director',     query: '"Risk Management Director" institution corporation USA "document" OR "audit" contact email' },

  // ── TIER 3: Operations
  { industry: 'institutional', role: 'operations', tier: 'approver',   title: 'VP of Operations',             query: '"VP of Operations" large institution corporation USA "document" OR "records" contact email' },
  { industry: 'institutional', role: 'operations', tier: 'approver',   title: 'Shared Services Director',     query: '"Shared Services Director" corporation USA "document" OR "records management" contact email' },
  { industry: 'institutional', role: 'operations', tier: 'approver',   title: 'Procurement Operations Manager', query: '"Procurement Operations Manager" large corporation USA contact email' },

  // ── TIER 4: Healthcare
  { industry: 'institutional', role: 'healthcare', tier: 'expansion',  title: 'HIM Director',                 query: '"Health Information Management Director" OR "HIM Director" hospital USA contact email' },
  { industry: 'institutional', role: 'healthcare', tier: 'expansion',  title: 'Medical Records Director',     query: '"Medical Records Director" hospital health system USA contact email' },
  { industry: 'institutional', role: 'healthcare', tier: 'expansion',  title: 'Hospital Compliance Officer',  query: '"Compliance Officer" hospital OR "health system" USA "document" OR "records" contact email' },

  // ── TIER 5: Education
  { industry: 'institutional', role: 'education',  tier: 'expansion',  title: 'University Registrar',         query: '"University Registrar" OR "Registrar" university USA contact email 2024 2025' },
  { industry: 'institutional', role: 'education',  tier: 'expansion',  title: 'Records & Archives Director',  query: '"Records and Archives Director" OR "University Archivist" USA contact email' },

  // ── TIER 6: Financial Institutions
  { industry: 'institutional', role: 'financial',  tier: 'expansion',  title: 'Loan Documentation Manager',   query: '"Loan Documentation Manager" OR "Loan Docs Manager" bank USA contact email' },

  // ════════════════════════════════════════════════════════
  // TITLE & ESCROW — make every closing document provable
  // ════════════════════════════════════════════════════════
  { industry: 'title_escrow', role: 'title_ops',  tier: 'primary',    title: 'Escrow Officer',               query: '"Escrow Officer" OR "Senior Escrow Officer" title company USA contact email' },
  { industry: 'title_escrow', role: 'title_ops',  tier: 'primary',    title: 'Closing Agent / Manager',      query: '"Closing Agent" OR "Closing Manager" title company real estate USA contact email' },
  { industry: 'title_escrow', role: 'title_ops',  tier: 'primary',    title: 'Title Operations Manager',     query: '"Title Operations Manager" OR "Title Manager" "title company" USA contact email' },
  { industry: 'title_escrow', role: 'title_risk', tier: 'influencer', title: 'Title Underwriter',            query: '"Title Underwriter" "First American" OR "Fidelity National" OR "Stewart Title" OR "Old Republic" USA contact email' },
  { industry: 'title_escrow', role: 'title_risk', tier: 'influencer', title: 'Claims Counsel (Title)',       query: '"Claims Counsel" title insurance company USA contact email' },
  { industry: 'title_escrow', role: 'title_risk', tier: 'influencer', title: 'VP of Risk (Title)',           query: '"VP of Risk" OR "Risk Manager" "title insurance" OR "title company" USA contact email' },
  { industry: 'title_escrow', role: 'title_ops',  tier: 'approver',   title: 'Branch Manager (Title)',       query: '"Branch Manager" "title company" OR "title insurance" USA contact email' },

  // ════════════════════════════════════════════════════════
  // LEGAL — lock document integrity at creation
  // ════════════════════════════════════════════════════════
  { industry: 'legal', role: 'litigation',  tier: 'primary',    title: 'Litigation Support Director',  query: '"Litigation Support Director" OR "Litigation Support Manager" law firm USA contact email' },
  { industry: 'legal', role: 'litigation',  tier: 'primary',    title: 'E-Discovery Manager',          query: '"E-Discovery Manager" OR "eDiscovery Director" law firm USA contact email' },
  { industry: 'legal', role: 'transact',    tier: 'primary',    title: 'Real Estate Attorney',         query: '"real estate attorney" partner OR director "law firm" USA "title" OR "closing" contact email' },
  { industry: 'legal', role: 'legal_ops',   tier: 'influencer', title: 'Legal Operations Director',    query: '"Legal Operations Director" law firm USA contact email' },
  { industry: 'legal', role: 'transact',    tier: 'influencer', title: 'Corporate Transactional Attorney', query: 'corporate transactional attorney partner "law firm" USA "M&A" OR "document" contact email' },

  // ════════════════════════════════════════════════════════
  // INSURANCE (non-auto) — prove claim documents are unaltered
  // ════════════════════════════════════════════════════════
  { industry: 'insurance', role: 'claims',     tier: 'primary',    title: 'Claims Documentation Manager', query: '"Claims Documentation Manager" OR "Claims Operations Manager" insurance USA contact email' },
  { industry: 'insurance', role: 'claims',     tier: 'primary',    title: 'SIU Director',                 query: '"Special Investigations Unit Director" OR "SIU Director" insurance USA contact email' },
  { industry: 'insurance', role: 'underwrite', tier: 'influencer', title: 'Underwriting Documentation Lead', query: '"Underwriting Documentation" manager OR director insurance USA contact email' },
  { industry: 'insurance', role: 'claims',     tier: 'influencer', title: 'VP of Claims',                 query: '"VP of Claims" OR "Director of Claims" insurance company USA contact email' },
  { industry: 'insurance', role: 'compliance', tier: 'approver',   title: 'Insurance Compliance Director', query: '"Compliance Director" OR "Chief Compliance Officer" insurance company USA contact email' },

  // ════════════════════════════════════════════════════════
  // CONSTRUCTION & LIEN — lien and waiver integrity
  // ════════════════════════════════════════════════════════
  { industry: 'construction', role: 'lien',    tier: 'primary',    title: 'Lien Management Director',     query: '"Lien Management Director" OR "Lien Manager" construction USA contact email' },
  { industry: 'construction', role: 'lien',    tier: 'primary',    title: 'Contract Administrator',       query: '"Contract Administrator" construction "lien" OR "waiver" USA contact email' },
  { industry: 'construction', role: 'legal',   tier: 'influencer', title: 'Construction Counsel',         query: '"Construction Counsel" OR "Construction Attorney" law firm USA contact email' },
  { industry: 'construction', role: 'ops',     tier: 'influencer', title: 'Project Documentation Manager', query: '"Project Documentation Manager" construction USA contact email' },
  { industry: 'construction', role: 'finance', tier: 'approver',   title: 'CFO (Construction Firm)',      query: 'CFO "construction company" OR "general contractor" USA "lien" OR "contract" contact email' },

  // ════════════════════════════════════════════════════════
  // SUPPLY CHAIN / LOGISTICS — verifiable shipment proof
  // ════════════════════════════════════════════════════════
  { industry: 'supply_chain', role: 'trade_docs', tier: 'primary',    title: 'Trade Documentation Manager', query: '"Trade Documentation Manager" OR "Shipping Documentation" manager logistics USA contact email' },
  { industry: 'supply_chain', role: 'compliance', tier: 'primary',    title: 'Trade Compliance Director',   query: '"Trade Compliance Director" OR "Global Trade Compliance" manager USA contact email' },
  { industry: 'supply_chain', role: 'legal',      tier: 'influencer', title: 'Supply Chain Counsel',        query: '"Supply Chain Counsel" OR "Logistics Counsel" corporation USA contact email' },
  { industry: 'supply_chain', role: 'ops',        tier: 'influencer', title: 'VP of Logistics Operations',  query: '"VP of Logistics" OR "Director of Supply Chain" USA "documentation" OR "compliance" contact email' },

  // ════════════════════════════════════════════════════════
  // REGULATED INDUSTRIES — audit-proof regulatory records
  // ════════════════════════════════════════════════════════
  { industry: 'regulated', role: 'compliance', tier: 'primary',    title: 'Regulatory Compliance Director (Energy)', query: '"Regulatory Compliance Director" energy OR utility USA "document" OR "records" contact email' },
  { industry: 'regulated', role: 'compliance', tier: 'primary',    title: 'Regulatory Affairs Director (Pharma)',    query: '"Regulatory Affairs Director" pharmaceutical OR biotech USA "document" OR "records" contact email' },
  { industry: 'regulated', role: 'compliance', tier: 'primary',    title: 'Environmental Compliance Manager',       query: '"Environmental Compliance Manager" OR "EHS Compliance" director USA contact email' },
  { industry: 'regulated', role: 'records',    tier: 'influencer', title: 'Records & Information Manager',         query: '"Records and Information Manager" energy OR pharma OR utility USA contact email' },

  // ════════════════════════════════════════════════════════
  // ACCOUNTING / AUDIT — evidence assurance layer
  // ════════════════════════════════════════════════════════
  { industry: 'accounting', role: 'audit', tier: 'primary',    title: 'Audit Partner / Director',       query: 'audit partner OR director "Deloitte" OR "PwC" OR "EY" OR "KPMG" OR "BDO" USA contact email' },
  { industry: 'accounting', role: 'audit', tier: 'primary',    title: 'Assurance Services Director',    query: '"Assurance Services Director" OR "Assurance Partner" accounting firm USA contact email' },
  { industry: 'accounting', role: 'audit', tier: 'influencer', title: 'Forensic Accounting Director',   query: '"Forensic Accounting" director OR partner "accounting firm" USA contact email' },

  // ════════════════════════════════════════════════════════
  // PRIVATE EQUITY / M&A — lock deal documents at every stage
  // ════════════════════════════════════════════════════════
  { industry: 'pe_ma', role: 'deal',  tier: 'primary',    title: 'Due Diligence Director',         query: '"Due Diligence Director" OR "Head of Due Diligence" "private equity" USA contact email' },
  { industry: 'pe_ma', role: 'deal',  tier: 'primary',    title: 'VP of Transactions',             query: '"VP of Transactions" OR "Deal Director" "private equity" USA contact email' },
  { industry: 'pe_ma', role: 'legal', tier: 'influencer', title: 'M&A Counsel',                    query: '"M&A Counsel" OR "Mergers and Acquisitions Attorney" USA contact email' },
  { industry: 'pe_ma', role: 'ops',   tier: 'influencer', title: 'Portfolio Operations Director',  query: '"Portfolio Operations Director" "private equity" USA contact email' },
];

const INITIAL_EMAIL = (name, company, industry, role) => {
  const first = name.split(' ')[0];

  // ── Recorder / Clerk — "Prove document integrity when records are challenged"
  const recorder = `Hi ${first},

When a recorded document gets challenged — contested deed, disputed filing, chain-of-title dispute — your office has to prove it. The question isn't whether it's in your system. It's whether you can prove it hasn't been altered.

ProofDeed anchors documents to the Polygon blockchain at the moment of recording. Every document gets a tamper-proof, timestamped certificate that satisfies FRE Rule 901 in court. No system replacement. No document storage. Works alongside your existing workflow via API — live in days.

Several county offices are using this to get ahead of fraud liability before it becomes a headline.

See it in 2 minutes: proofdeed.com/demo

Would a 20-minute call this week make sense?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
gov@proofdeed.com | proofdeed.com`;

  // ── Legal / Risk / Audit — "Reduce exposure when document authenticity is disputed"
  const legal = `Hi ${first},

When document authenticity gets disputed in litigation, the question your office faces is: can you prove the document hasn't been altered since it was created? Timestamps in internal systems don't answer that. A court wants independent, tamper-proof proof.

ProofDeed creates a blockchain-anchored certificate at the moment a document is recorded — independently verifiable by any court, auditor, or opposing counsel without access to your internal systems. FRE Rule 901 compliant. No system changes required.

The cost of a single disputed record averages $50,000 in legal fees. The cost to protect against it is a fraction of that.

See it in 2 minutes: proofdeed.com/demo

Worth a 20-minute conversation?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
gov@proofdeed.com | proofdeed.com`;

  // ── IT / CIO / Digital Services — "No system changes, no document storage, low-risk deployment"
  const it = `Hi ${first},

I'll keep this short because I know your plate is full.

ProofDeed adds tamper-proof document certification to your existing workflow — no system replacement, no document storage on our end, single API call. Most county offices are live in under a week with no impact on existing infrastructure.

It creates a blockchain-anchored record for each document at the moment it's processed — independently verifiable proof of integrity and timestamp that holds up in court under FRE Rule 901.

No new user training. No data migration. No long-term lock-in.

See it in 2 minutes: proofdeed.com/demo

Would 20 minutes be worth it to see the integration?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
gov@proofdeed.com | proofdeed.com`;

  // ── Procurement / Budget — "Fixed-cost pilot, no long-term commitment"
  const procurement = `Hi ${first},

If your office is evaluating document integrity solutions, I want to make this easy.

ProofDeed offers a fixed-cost 45-day Government Pilot at $15,000 — up to 50,000 certifications, full API access, no variable costs, no long-term commitment. If it works, you continue at standard volume pricing. If not, your certified records remain on-chain permanently regardless.

It anchors documents to the Polygon blockchain at the moment of processing — tamper-proof, court-admissible proof under FRE Rule 901. Single API integration. No system replacement.

ACH and purchase order accepted.

See it in 2 minutes: proofdeed.com/demo

Worth a quick call to discuss the pilot structure?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
gov@proofdeed.com | proofdeed.com`;

  // ── Auto Dealer / F&I / Title — "proof of ownership + transaction integrity"
  const auto_dealer = `Hi ${first},

Every title transfer, lien release, and ownership record your operation processes is a liability the moment it's disputed. A forged title, an altered odometer disclosure, a backdated transfer — if you can't prove the document's integrity at the moment it was created, you're defending yourself without evidence.

ProofDeed anchors each document to the Polygon blockchain at the moment it's processed — creating tamper-proof proof of ownership and transaction integrity that holds up in court under FRE Rule 901. No system replacement. Single API call. Live in days.

One disputed title can cost more than a full year of protection.

See it in 2 minutes: proofdeed.com/demo

Worth a 20-minute call this week?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
gov@proofdeed.com | proofdeed.com`;

  // ── Auto Lender / Collateral / Lien — "lien accuracy + title chain integrity"
  const auto_lender = `Hi ${first},

Lien accuracy and title chain integrity are the foundation of your collateral position. When a borrower defaults and the title history is challenged — altered records, forged releases, disputed ownership — your ability to recover depends entirely on whether you can prove the documents are authentic.

ProofDeed creates a blockchain-anchored certificate for every loan document and lien record at the moment it's processed — independently verifiable proof under FRE Rule 901. No system replacement. Single API call.

See it in 2 minutes: proofdeed.com/demo

Would 20 minutes be worth it to walk through how it fits your workflow?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
gov@proofdeed.com | proofdeed.com`;

  // ── Auto Auction / Remarketing — "chain of custody for high-volume transfers"
  const auto_auction = `Hi ${first},

At the volume your operation processes, every vehicle transfer is a potential chain-of-custody dispute. Odometer fraud, salvage title laundering, forged ownership records — the liability lands on whoever processed the last transaction without proof.

ProofDeed anchors vehicle records to the Polygon blockchain at the moment of transfer — tamper-proof chain of custody that's independently verifiable and court-admissible under FRE Rule 901. No system replacement. Single API call.

See it in 2 minutes: proofdeed.com/demo

Worth a quick call this week?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
gov@proofdeed.com | proofdeed.com`;

  // ── Institutional Compliance / Records / GRC — "audit-proof document integrity"
  const inst_compliance = `Hi ${first},

When an audit, dispute, or regulatory review puts a document's authenticity in question, your organization has to prove it — not just that it exists in your system, but that it hasn't been altered since it was created. Most document management systems can't answer that. Courts and regulators increasingly expect independent proof.

ProofDeed creates a blockchain-anchored certificate for every critical document at the moment it's processed — tamper-proof, independently verifiable proof under FRE Rule 901. No system replacement. No document storage. Single API call.

See it in 2 minutes: proofdeed.com/demo

Worth a 20-minute conversation?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
gov@proofdeed.com | proofdeed.com`;

  // ── Institutional Legal / Risk — "verifiable proof for disputes and regulatory reviews"
  const inst_legal = `Hi ${first},

When document authenticity is disputed in litigation or a regulatory review, the question is simple: can you prove this document is unchanged from when it was created? Metadata in your DMS won't hold up. A court wants independent, tamper-proof evidence.

ProofDeed creates a blockchain-anchored record for every critical document at the moment it's processed — independently verifiable by any court or regulator without access to your internal systems. FRE Rule 901 compliant. No system changes required.

The cost of a single disputed document in litigation dwarfs the annual cost of protecting against it.

See it in 2 minutes: proofdeed.com/demo

Worth a quick call?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
gov@proofdeed.com | proofdeed.com`;

  // ── Healthcare — "medical records integrity + audit trail"
  const inst_healthcare = `Hi ${first},

When a patient record, consent form, or clinical document is disputed — in litigation, an audit, or a regulatory review — your organization has to prove it hasn't been altered. Most EHR and records systems log access but can't independently prove document integrity to a court or regulator.

ProofDeed anchors documents to the Polygon blockchain at the moment they're processed — tamper-proof, independently verifiable proof that holds up under FRE Rule 901 and strengthens your audit trail. No system replacement. Single API call.

See it in 2 minutes: proofdeed.com/demo

Would 20 minutes make sense this week?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
gov@proofdeed.com | proofdeed.com`;

  // ── Title & Escrow — "make every closing document provable and tamper-proof"
  const title_escrow = `Hi ${first},

Every real estate closing generates a stack of documents that can be disputed years later — deeds, settlement statements, title commitments, wire instructions. Title fraud and post-closing disputes are rising, and the organizations that can prove document integrity at the moment of closing are in the strongest position when they do.

ProofDeed anchors every closing document to the Polygon blockchain at the moment it's processed — tamper-proof, timestamped proof that's court-admissible under FRE Rule 901. No system replacement. Single API call. Live in days.

The cost of a single disputed closing dwarfs the annual cost of protection.

See it in 2 minutes: proofdeed.com/demo

Worth a 20-minute call this week?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
gov@proofdeed.com | proofdeed.com`;

  // ── Legal / Law Firms — "lock document integrity at creation so it holds up in court"
  const legal_firm = `Hi ${first},

The most damaging thing that can happen to a document in litigation is for opposing counsel to allege it was altered after creation. If you can't prove the document is unchanged from the moment it was drafted, you're defending the document instead of the case.

ProofDeed anchors documents to the Polygon blockchain at the moment they're created — tamper-proof proof of existence and integrity that's independently verifiable and court-admissible under FRE Rule 901. No system changes. No document storage.

See it in 2 minutes: proofdeed.com/demo

Would 20 minutes make sense to walk through how it works?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
gov@proofdeed.com | proofdeed.com`;

  // ── Insurance (non-auto) — "prove claim documents haven't been altered"
  const insurance_gen = `Hi ${first},

When a claim goes into dispute or a fraud investigation, the question your team faces is: can you prove the claim documents are unchanged from when they were submitted? Altered policies, backdated records, tampered loss documentation — if you can't prove integrity independently, you're vulnerable.

ProofDeed creates a blockchain-anchored certificate for every claim document at the moment it's processed — tamper-proof, independently verifiable proof under FRE Rule 901. No system replacement. Single API call.

See it in 2 minutes: proofdeed.com/demo

Worth a quick call to see how it fits your workflow?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
gov@proofdeed.com | proofdeed.com`;

  // ── Construction & Lien — "ensure lien and waiver documents can't be challenged later"
  const construction = `Hi ${first},

Mechanic's liens, lien waivers, and release documents are among the most frequently disputed in construction litigation. A conditional waiver that looks like an unconditional one. A lien release with an altered amount. When the dispute hits, whoever processed the document has to prove it.

ProofDeed anchors lien and contract documents to the Polygon blockchain at the moment they're signed — tamper-proof proof of the exact document at the exact time, court-admissible under FRE Rule 901. No system replacement. Single API call.

See it in 2 minutes: proofdeed.com/demo

Would 20 minutes be worth it?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
gov@proofdeed.com | proofdeed.com`;

  // ── Supply Chain / Logistics — "verifiable proof of shipment documentation"
  const supply_chain = `Hi ${first},

Bill of lading disputes, altered delivery records, tampered customs documentation — when a shipment claim goes into dispute, the documentation is the evidence. If you can't prove the document's integrity at the moment it was created, you're arguing about the paper instead of the shipment.

ProofDeed anchors trade and logistics documents to the Polygon blockchain at the moment they're processed — tamper-proof, independently verifiable proof under FRE Rule 901. No system replacement. Single API call.

See it in 2 minutes: proofdeed.com/demo

Worth a quick call?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
gov@proofdeed.com | proofdeed.com`;

  // ── Regulated Industries — "audit-proof regulatory records"
  const regulated = `Hi ${first},

When a regulator or auditor challenges a compliance document — an environmental filing, a pharma submission, an energy report — the question isn't just whether you have it. It's whether you can prove it hasn't been altered since it was filed.

ProofDeed creates a blockchain-anchored certificate for every regulatory document at the moment it's submitted — independently verifiable proof of integrity and timestamp under FRE Rule 901. No system replacement. No document storage. Single API call.

See it in 2 minutes: proofdeed.com/demo

Would 20 minutes make sense this week?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
gov@proofdeed.com | proofdeed.com`;

  // ── Accounting / Audit — "evidence assurance layer"
  const accounting = `Hi ${first},

Audit work depends on document integrity — but auditors verify what clients provide, not whether the underlying documents have been altered before they arrive. When an audit is challenged or a fraud surfaces, the question is whether the documents your team reviewed were the originals.

ProofDeed creates a blockchain-anchored record at the moment a document is created — independently verifiable proof that it hasn't been altered since. Not a replacement for your process — an evidence assurance layer underneath it.

See it in 2 minutes: proofdeed.com/demo

Worth a 20-minute conversation?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
gov@proofdeed.com | proofdeed.com`;

  // ── Private Equity / M&A — "lock deal documents at every stage"
  const pe_ma = `Hi ${first},

In M&A and PE deals, documents change hands across dozens of parties over months. By the time a dispute surfaces — a rep and warranty claim, a contested disclosure, a post-close disagreement — the question is which version of the document was signed and when. If you can't prove it independently, you're litigating the paper trail instead of the deal.

ProofDeed anchors deal documents to the Polygon blockchain at each stage — tamper-proof proof of the exact document at the exact time, court-admissible under FRE Rule 901. No system replacement. Single API call.

See it in 2 minutes: proofdeed.com/demo

Worth a quick call?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
gov@proofdeed.com | proofdeed.com`;

  const byRole = {
    // Government
    recorder:       recorder,
    legal:          legal,
    risk:           legal,
    it:             it,
    procurement:    procurement,
    expansion:      recorder,
    // Automotive
    dealer:         auto_dealer,
    lender:         auto_lender,
    auction:        auto_auction,
    fleet:          auto_auction,
    digital:        auto_dealer,
    insurance:      auto_lender,
    // Institutional
    compliance:     inst_compliance,
    operations:     inst_compliance,
    education:      inst_compliance,
    financial:      inst_legal,
    healthcare:     inst_healthcare,
    // Title & Escrow
    title_ops:      title_escrow,
    title_risk:     title_escrow,
    // Legal
    litigation:     legal_firm,
    transact:       legal_firm,
    legal_ops:      legal_firm,
    // Insurance
    claims:         insurance_gen,
    underwrite:     insurance_gen,
    // Construction
    lien:           construction,
    // Supply Chain
    trade_docs:     supply_chain,
    // Regulated
    records:        regulated,
    // Accounting
    audit:          accounting,
    // PE / M&A
    deal:           pe_ma,
    // Shared fallbacks
    ops:            inst_compliance,
    finance:        inst_legal,
  };

  return byRole[role] || recorder;
};

function calcPriorityScore(title, industry, role) {
  let score = 0;
  const t = (title || '').toLowerCase();
  const ind = (industry || '');
  const r = (role || '');

  // +3 Core buyer role
  if (['recorder','dealer','compliance','title_ops','claims','lien','audit','deal','litigation','transact'].includes(r)) score += 3;

  // +3 High document volume industry
  if (['government','title_escrow','legal','auto','construction','pe_ma'].includes(ind)) score += 3;

  // +2 Regulated industry
  if (['government','regulated','institutional','insurance','accounting'].includes(ind)) score += 2;

  // +3 Risk signal in title
  if (['risk','compliance','fraud','audit','legal','counsel','investigation','integrity','claims','lien'].some(k => t.includes(k))) score += 3;

  // +1 Director or above
  if (['director','vp ','vice president','chief','head of','partner','officer','president','counsel','registrar'].some(k => t.includes(k))) score += 1;

  return Math.min(score, 12);
}

function priorityLabel(score) {
  if (score >= 7) return 'hot';
  if (score >= 5) return 'warm';
  return 'cold';
}

async function runLeadEngine() {
  if (!process.env.ANTHROPIC_API_KEY || !process.env.RESEND_API_KEY) {
    console.log(`[LeadEngine] Missing API keys — ANTHROPIC: ${!!process.env.ANTHROPIC_API_KEY}, RESEND: ${!!process.env.RESEND_API_KEY}`);
    return;
  }

  // Get current rotation index
  const idxRow = await pool.query(`SELECT value FROM lead_engine_state WHERE key='rotation_index'`).catch(() => ({ rows: [] }));
  const currentIdx = idxRow.rows[0] ? parseInt(idxRow.rows[0].value) : 0;
  const target = LEAD_TARGETS[currentIdx % LEAD_TARGETS.length];
  const nextIdx = (currentIdx + 1) % LEAD_TARGETS.length;

  // Save next index immediately so crashes don't repeat the same target
  await pool.query(
    `INSERT INTO lead_engine_state (key, value, updated_at) VALUES ('rotation_index',$1,NOW())
     ON CONFLICT (key) DO UPDATE SET value=$1, updated_at=NOW()`,
    [String(nextIdx)]
  ).catch(() => {});

  console.log(`[LeadEngine] Running — ${target.title} / ${target.industry}`);

  try {
    const Anthropic = (await import('@anthropic-ai/sdk')).default;
    const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

    const response = await anthropic.messages.create({
      model: 'claude-opus-4-6',
      max_tokens: 2000,
      tools: [{ type: 'web_search_20250305', name: 'web_search' }],
      messages: [{
        role: 'user',
        content: `Search the web and find 6 real ${target.title} executives at ${target.industry.replace(/_/g,' ')} organizations in the USA. Check company websites, press releases, conference speaker lists, and news articles to find real people currently in this role. For each person, find their full name, exact title, company name, and most likely work email address (check the company website for email format, otherwise guess firstname.lastname@companydomain.com). Return ONLY a valid JSON array with no other text before or after it, like this: [{"name":"Full Name","title":"Exact Title","company":"Company Name","email":"email@company.com","industry":"${target.industry}","source":"url"}]`
      }]
    });

    // Extract JSON from response
    const text = response.content.filter((b) => b.type === 'text').map((b) => b.text).join('');
    console.log('[LeadEngine] Response preview:', text.substring(0, 300));
    const match = text.match(/\[[\s\S]*\]/);
    if (!match) { console.log('[LeadEngine] No JSON found in response — full text:', text.substring(0, 500)); return; }
    const leads = JSON.parse(match[0]);
    console.log(`[LeadEngine] Found ${leads.length} leads from Claude`);

    const { Resend } = await import('resend');
    const resend = new Resend(process.env.RESEND_API_KEY);

    let sent = 0, skipped = 0;
    for (const lead of leads) {
      if (!lead.email || !lead.name || !lead.company) { skipped++; continue; }
      // Deduplicate
      const exists = await pool.query('SELECT id FROM outreach_contacts WHERE email=$1', [lead.email.toLowerCase()]);
      if (exists.rows.length > 0) { skipped++; continue; }

      const replyTag = crypto.randomBytes(8).toString('hex');
      const emailBody = INITIAL_EMAIL(lead.name, lead.company, lead.industry || target.industry, target.role);
      const subject = `Blockchain Document Certification for ${lead.company}`;

      try {
        const result = await resend.emails.send({
          from: 'Scott Kiersten <gov@send.proofdeed.com>',
          reply_to: `reply+${replyTag}@send.proofdeed.com`,
          to: lead.email,
          subject,
          text: emailBody,
        });

        const pscore = calcPriorityScore(lead.title, lead.industry || target.industry, target.role);
        const useCase = `${target.title} — ${(lead.industry || target.industry).replace(/_/g,' ')}`;
        await pool.query(
          `INSERT INTO outreach_contacts (name, email, company, title, industry, tier, priority_score, pipeline_stage, pain_status, use_case, status, reply_to_tag, resend_message_id, first_sent_at, last_contact_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,'contacted','unaware',$8,'sent',$9,$10,NOW(),NOW())`,
          [lead.name, lead.email.toLowerCase(), lead.company, lead.title, lead.industry || target.industry, target.tier || 'primary', pscore, useCase, replyTag, result.data?.id || null]
        );
        await pool.query(
          `INSERT INTO outreach_events (contact_id, event_type, event_source, metadata, occurred_at)
           SELECT id, 'sent', 'lead_engine', $1, NOW() FROM outreach_contacts WHERE email=$2`,
          [JSON.stringify({ subject, source: lead.source }), lead.email.toLowerCase()]
        );

        sent++;
        console.log(`[LeadEngine] Sent → ${lead.name} (${lead.company})`);
        await new Promise(r => setTimeout(r, 3000));
      } catch (e) {
        console.error(`[LeadEngine] Send fail ${lead.email}:`, e.message);
        skipped++;
      }
    }

    // Update rotation index
    await pool.query(
      `INSERT INTO lead_engine_state (key, value, updated_at) VALUES ('rotation_index',$1,NOW())
       ON CONFLICT (key) DO UPDATE SET value=$1, updated_at=NOW()`,
      [String(nextIdx)]
    );
    await pool.query(
      `INSERT INTO lead_engine_state (key, value, updated_at) VALUES ('last_run',$1,NOW())
       ON CONFLICT (key) DO UPDATE SET value=$1, updated_at=NOW()`,
      [new Date().toISOString()]
    );
    await pool.query(
      `INSERT INTO lead_engine_state (key, value, updated_at) VALUES ('last_result',$1,NOW())
       ON CONFLICT (key) DO UPDATE SET value=$1, updated_at=NOW()`,
      [JSON.stringify({ target: `${target.title} / ${target.industry}`, sent, skipped, total: leads.length })]
    );

    console.log(`[LeadEngine] Done. Sent: ${sent}, Skipped: ${skipped}, Next: ${LEAD_TARGETS[nextIdx].title}/${LEAD_TARGETS[nextIdx].industry}`);
  } catch (err) {
    console.error('[LeadEngine] Error:', err.message);
  }
}

// Run Tuesday, Wednesday, Thursday at 8am PT (11am ET — peak B2B open rates)
cron.schedule('0 8 * * 2,3,4', () => runLeadEngine(), { timezone: 'America/Los_Angeles' });

/* ---------------- Lead Engine API ----------------  */
app.get(['/api/admin/lead-engine', '/admin/lead-engine'], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: 'Unauthorized.' });
  try {
    const rows = await pool.query('SELECT key, value, updated_at FROM lead_engine_state').catch(() => ({ rows: [] }));
    const state = {};
    rows.rows.forEach(r => { state[r.key] = { value: r.value, updated_at: r.updated_at }; });
    res.json({
      enabled: true,
      targets: LEAD_TARGETS.map((t, i) => ({ ...t, index: i })),
      currentIndex: parseInt(state.rotation_index?.value || '0'),
      lastRun: state.last_run?.value || null,
      lastResult: state.last_result?.value ? JSON.parse(state.last_result.value) : null,
      nextTarget: LEAD_TARGETS[parseInt(state.rotation_index?.value || '0') % LEAD_TARGETS.length],
      schedule: 'Every Monday 9am PT',
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post(['/api/admin/lead-engine/run', '/admin/lead-engine/run'], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: 'Unauthorized.' });
  res.json({ success: true, message: 'Lead engine started — check CRM in ~60 seconds.' });
  runLeadEngine(); // fire and forget
});

/* ---------------- Outreach Autopilot (daily 8am UTC) ---------------- */
async function sendOutreachFollowUp(contact, day) {
  if (!process.env.RESEND_API_KEY) return;
  const { Resend } = await import('resend');
  const resend = new Resend(process.env.RESEND_API_KEY);
  const first = contact.name.split(' ')[0];

  let text, subject;
  if (day === 7) {
    text = `Hi ${first},

Following up on my note from last week about blockchain document certification for ${contact.company}.

Document fraud and post-transaction disputes are rising across every industry that handles high-value records — and organizations that have anchored their document workflows to blockchain certification are in the strongest position to protect themselves and satisfy court admissibility requirements under FRE Rule 901.

ProofDeed requires no system replacement, integrates via a single lightweight API call, and can go live within days of a decision.

See it live in 2 minutes: proofdeed.com/demo

Would you have 20 minutes this week for a quick walkthrough?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
gov@proofdeed.com | proofdeed.com`;
    subject = `Re: Blockchain Document Certification for ${contact.company}`;
  } else if (day === 14) {
    text = `Hi ${first},

I wanted to reach out one more time regarding blockchain document certification for ${contact.company}.

A quick question: is document authenticity and fraud prevention something on your radar for this year, or is the timing simply not right?

Either answer helps me — I don't want to keep following up if it's not relevant. But if it is, I'd love to show you how organizations like yours are using ProofDeed to anchor their most critical documents to the blockchain in under a minute.

See it live: proofdeed.com/demo

Happy to work around your schedule if a 15-minute call makes sense.

Best,
Scott Kiersten
Founder & CEO, ProofDeed
gov@proofdeed.com | proofdeed.com`;
    subject = `Re: Blockchain Document Certification for ${contact.company}`;
  } else {
    text = `Hi ${first},

I've reached out a couple of times about blockchain document certification for ${contact.company} and haven't heard back — so I'll assume the timing isn't right and close out my follow-ups.

If that changes, I'm happy to reconnect. ProofDeed certifies documents on the Polygon blockchain with court-admissible proof under FRE Rule 901 — no system replacement, live in days.

One last ask: if there's someone else at ${contact.company} better suited for this conversation, I'd appreciate a quick introduction.

Either way, appreciate your time and wish you well.

Best,
Scott Kiersten
Founder & CEO, ProofDeed
gov@proofdeed.com | proofdeed.com`;
    subject = `Re: Blockchain Document Certification for ${contact.company}`;
  }

  const replyTag = crypto.randomBytes(8).toString('hex');
  await resend.emails.send({
    from: 'Scott Kiersten <gov@send.proofdeed.com>',
    reply_to: `reply+${replyTag}@send.proofdeed.com`,
    to: contact.email,
    subject,
    text,
  });

  await pool.query(
    `UPDATE outreach_contacts SET status='sent', last_contact_at=NOW(), reply_to_tag=$1 WHERE id=$2`,
    [replyTag, contact.id]
  );
  await pool.query(
    `INSERT INTO outreach_events (contact_id, event_type, event_source, metadata, occurred_at)
     VALUES ($1, $2, 'autopilot', $3, NOW())`,
    [contact.id, day === 7 ? 'follow_up_1' : 'breakup', JSON.stringify({ subject, day })]
  );
}

cron.schedule('0 8 * * *', async () => {
  console.log('[Autopilot] Running daily follow-up check...');
  try {
    // Day 7: no reply, first_sent_at between 7-8 days ago — skip dead/lost
    const day7 = await pool.query(`
      SELECT * FROM outreach_contacts
      WHERE status NOT IN ('replied','in_talks','closed_won','closed_lost','bounced','complained','unsubscribed')
      AND pipeline_stage NOT IN ('pilot_discussed','pilot_sent','pilot_approved','closed','qualified')
      AND first_sent_at <= NOW() - INTERVAL '7 days'
      AND first_sent_at > NOW() - INTERVAL '8 days'
    `);
    for (const c of day7.rows) {
      try { await sendOutreachFollowUp(c, 7); console.log(`[Autopilot] Day 7 → ${c.name}`); }
      catch (e) { console.error(`[Autopilot] Day 7 fail ${c.email}:`, e.message); }
      await new Promise(r => setTimeout(r, 3000));
    }

    // Day 14: second follow-up — no reply, first_sent_at between 14-15 days ago
    const day14 = await pool.query(`
      SELECT * FROM outreach_contacts
      WHERE status NOT IN ('replied','in_talks','closed_won','closed_lost','bounced','complained','unsubscribed')
      AND pipeline_stage NOT IN ('pilot_discussed','pilot_sent','pilot_approved','closed','qualified')
      AND first_sent_at <= NOW() - INTERVAL '14 days'
      AND first_sent_at > NOW() - INTERVAL '15 days'
    `);
    for (const c of day14.rows) {
      try { await sendOutreachFollowUp(c, 14); console.log(`[Autopilot] Day 14 → ${c.name}`); }
      catch (e) { console.error(`[Autopilot] Day 14 fail ${c.email}:`, e.message); }
      await new Promise(r => setTimeout(r, 3000));
    }

    // Day 21: breakup — no reply, first_sent_at between 21-22 days ago
    const day21 = await pool.query(`
      SELECT * FROM outreach_contacts
      WHERE status NOT IN ('replied','in_talks','closed_won','closed_lost','bounced','complained','unsubscribed')
      AND pipeline_stage NOT IN ('pilot_discussed','pilot_sent','pilot_approved','closed','qualified')
      AND first_sent_at <= NOW() - INTERVAL '21 days'
      AND first_sent_at > NOW() - INTERVAL '22 days'
    `);
    for (const c of day21.rows) {
      try {
        await sendOutreachFollowUp(c, 21);
        await pool.query(`UPDATE outreach_contacts SET status='closed_lost' WHERE id=$1`, [c.id]);
        console.log(`[Autopilot] Day 21 breakup → ${c.name}`);
      }
      catch (e) { console.error(`[Autopilot] Day 21 fail ${c.email}:`, e.message); }
      await new Promise(r => setTimeout(r, 3000));
    }

    console.log(`[Autopilot] Done. Day7: ${day7.rows.length}, Day14: ${day14.rows.length}, Day21: ${day21.rows.length}`);
  } catch (err) {
    console.error('[Autopilot] Cron error:', err.message);
  }
}, { timezone: 'America/Los_Angeles' });

/* ---------------- System Health Monitor ---------------- */
const ADMIN_ALERT_EMAIL = process.env.MAIL_TO || 'scott@proofdeed.com';
let lastAlertSent = {};

async function sendAlertEmail(subject, body) {
  const domain = process.env.MAILGUN_DOMAIN;
  const key = process.env.MAILGUN_API_KEY;
  if (!domain || !key) return;
  await fetch(`https://api.mailgun.net/v3/${domain}/messages`, {
    method: 'POST',
    headers: {
      Authorization: 'Basic ' + Buffer.from('api:' + key).toString('base64'),
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      from: process.env.MAIL_FROM || `ProofDeed <noreply@${domain}>`,
      to: ADMIN_ALERT_EMAIL,
      subject,
      text: body,
    }),
  });
}

async function runHealthChecks() {
  const checks = [];
  const now = Date.now();

  // 1. Database
  try {
    await pool.query('SELECT 1');
    checks.push({ name: 'Database', ok: true });
  } catch (e) {
    checks.push({ name: 'Database', ok: false, error: e.message });
  }

  // 2. Stripe
  try {
    await stripe.balance.retrieve();
    checks.push({ name: 'Stripe', ok: true });
  } catch (e) {
    checks.push({ name: 'Stripe', ok: false, error: e.message });
  }

  // 3. Resend API
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'GET',
      headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}` },
    });
    checks.push({ name: 'Resend', ok: r.status !== 500, error: r.status >= 500 ? `HTTP ${r.status}` : null });
  } catch (e) {
    checks.push({ name: 'Resend', ok: false, error: e.message });
  }

  // 4. Mailgun
  try {
    const domain = process.env.MAILGUN_DOMAIN;
    const key = process.env.MAILGUN_API_KEY;
    if (domain && key) {
      const r = await fetch(`https://api.mailgun.net/v3/domains/${domain}`, {
        headers: { Authorization: 'Basic ' + Buffer.from('api:' + key).toString('base64') },
      });
      checks.push({ name: 'Mailgun', ok: r.ok, error: r.ok ? null : `HTTP ${r.status}` });
    } else {
      checks.push({ name: 'Mailgun', ok: false, error: 'Keys not set' });
    }
  } catch (e) {
    checks.push({ name: 'Mailgun', ok: false, error: e.message });
  }

  const failures = checks.filter(c => !c.ok);

  // Alert on new failures (don't spam — once per hour per service)
  for (const f of failures) {
    const lastSent = lastAlertSent[f.name] || 0;
    if (now - lastSent > 60 * 60 * 1000) {
      lastAlertSent[f.name] = now;
      await sendAlertEmail(
        `🚨 ProofDeed Alert: ${f.name} is DOWN`,
        `ProofDeed system alert — ${new Date().toLocaleString()}\n\n${f.name} is not responding.\n\nError: ${f.error}\n\nCheck DigitalOcean logs immediately.\nhttps://cloud.digitalocean.com`
      ).catch(() => {});
      console.error(`[HealthMonitor] ALERT sent — ${f.name} down: ${f.error}`);
    }
  }

  // Clear alert state when service recovers
  for (const c of checks.filter(c => c.ok)) {
    if (lastAlertSent[c.name]) {
      delete lastAlertSent[c.name];
      console.log(`[HealthMonitor] ${c.name} recovered.`);
    }
  }

  return checks;
}

// Check every 15 minutes
cron.schedule('*/15 * * * *', () => runHealthChecks());

// Daily summary at 8am PT
cron.schedule('0 8 * * *', async () => {
  const checks = await runHealthChecks();
  const allOk = checks.every(c => c.ok);
  const lines = checks.map(c => `${c.ok ? '✅' : '❌'} ${c.name}${c.error ? ': ' + c.error : ''}`).join('\n');
  await sendAlertEmail(
    allOk ? '✅ ProofDeed Daily Health Check — All Systems OK' : '⚠️ ProofDeed Daily Health Check — Issues Detected',
    `ProofDeed Daily System Report — ${new Date().toLocaleDateString()}\n\n${lines}\n\nAdmin: https://proofdeed.com/admin`
  ).catch(() => {});
  console.log(`[HealthMonitor] Daily summary sent. All OK: ${allOk}`);
}, { timezone: 'America/Los_Angeles' });

// Expose health check endpoint for manual trigger
app.get(['/api/admin/health-check', '/admin/health-check'], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: 'Unauthorized.' });
  const checks = await runHealthChecks();
  const allOk = checks.every(c => c.ok);
  res.json({ allOk, checks, timestamp: new Date().toISOString() });
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
