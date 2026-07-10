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
import multer from 'multer';
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

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
// DigitalOcean strips /api prefix — these are the routes that actually get hit externally
app.get("/health", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");
    res.status(200).json({ status: "ok", database: result.rows[0] });
  } catch (e) {
    res.status(500).json({ status: "error", error: e.message });
  }
});

app.get("/health/auth", async (req, res) => {
  try {
    await pool.query("SELECT COUNT(*) FROM magic_links WHERE expires_at > NOW()");
    const testToken = jwt.sign({ health: true }, process.env.JWT_SECRET, { expiresIn: "1m" });
    jwt.verify(testToken, process.env.JWT_SECRET);
    res.json({ status: "ok", auth: "healthy" });
  } catch (e) {
    res.status(500).json({ status: "error", error: e.message });
  }
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
  const raw = ['/api/stripe-webhook', '/stripe-webhook', '/api/webhooks/resend', '/webhooks/resend', '/api/webhooks/resend-inbound', '/webhooks/resend-inbound'];
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

/* ---------------- Auth Health (for monitoring) ---------------- */
app.get("/api/health/auth", async (req, res) => {
  try {
    await pool.query("SELECT COUNT(*) FROM magic_links WHERE expires_at > NOW()");
    const testToken = jwt.sign({ health: true }, process.env.JWT_SECRET, { expiresIn: "1m" });
    jwt.verify(testToken, process.env.JWT_SECRET);
    res.json({ status: "ok", auth: "healthy", jwt: testToken });
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

/* ---------------- FIELD-LEVEL CERTIFY ---------------- */
// Hashes each field individually so you can prove WHICH field changed, not just that something did.
// Use case: financial sheets, automotive deal jackets, medical records, subscription agreements.
app.post("/api/v1/certify/fields", authenticateApiKey, async (req, res) => {
  try {
    const { fields, label, metadata } = req.body;
    // fields = { vin: "1HGBH41JXMN109186", odometer: "45231", price: "24500.00", ... }
    if (!fields || typeof fields !== 'object' || Array.isArray(fields)) {
      return res.status(400).json({ error: 'fields must be a key/value object.' });
    }

    const proofId = 'PD-F-' + Date.now() + '-' + crypto.randomBytes(3).toString('hex');
    const timestamp = new Date().toISOString();

    // Hash each field individually
    const fieldHashes = {};
    for (const [key, value] of Object.entries(fields)) {
      fieldHashes[key] = crypto.createHash('sha256').update(String(value)).digest('hex');
    }

    // Root hash = hash of all field hashes combined (order-stable via sorted keys)
    const rootInput = Object.keys(fieldHashes).sort().map(k => `${k}:${fieldHashes[k]}`).join('|');
    const rootHash = crypto.createHash('sha256').update(rootInput).digest('hex');

    await pool.query(
      `INSERT INTO certifications (certification_id, hash, polygon_tx, api_key_email, ip_address, created_at)
       VALUES ($1, $2, NULL, $3, $4, NOW()) ON CONFLICT (certification_id) DO NOTHING`,
      [proofId, rootHash, req.apiKey.email, req.ip || req.headers['x-forwarded-for'] || null]
    );

    await pool.query(
      'UPDATE api_keys SET used_this_month = used_this_month + 1 WHERE api_key = $1',
      [req.apiKey.api_key]
    );

    if (req.apiKey.stripe_subscription_item_id) {
      await reportUsageToStripe(req.apiKey.stripe_subscription_item_id, 1);
    }

    res.json({
      proofId, timestamp, rootHash, fieldHashes, label: label || null,
      verifyUrl: `https://proofdeed.com/verify/${rootHash}`,
      note: 'Each fieldHash proves the value of that field at this timestamp. rootHash proves all fields together.'
    });

    // Anchor root hash to blockchain in background
    anchorToPolygon(rootHash).then(async (txHash) => {
      await pool.query('UPDATE certifications SET polygon_tx=$1 WHERE certification_id=$2', [txHash, proofId]);
      if (req.apiKey.webhook_url) {
        fetch(req.apiKey.webhook_url, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ event: 'certification.fields.created', proofId, rootHash, fieldHashes, timestamp, polygon_tx: txHash, label })
        }).catch(() => {});
      }
    }).catch(err => console.error('Field cert blockchain anchor failed:', err.message));

  } catch (err) {
    console.error('Field certify error:', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

/* ---------------- FIELD VERIFY — check if a specific field has changed ---------------- */
app.post("/api/v1/verify/fields", async (req, res) => {
  try {
    const { proofId, fields } = req.body;
    if (!proofId || !fields) return res.status(400).json({ error: 'proofId and fields required.' });

    const cert = await pool.query('SELECT * FROM certifications WHERE certification_id=$1', [proofId]);
    if (!cert.rows[0]) return res.status(404).json({ error: 'Proof not found.' });

    // Recompute field hashes from provided values
    const recomputedHashes = {};
    for (const [key, value] of Object.entries(fields)) {
      recomputedHashes[key] = crypto.createHash('sha256').update(String(value)).digest('hex');
    }
    const rootInput = Object.keys(recomputedHashes).sort().map(k => `${k}:${recomputedHashes[k]}`).join('|');
    const recomputedRoot = crypto.createHash('sha256').update(rootInput).digest('hex');

    const intact = recomputedRoot === cert.rows[0].hash;
    res.json({
      intact, proofId,
      originalRootHash: cert.rows[0].hash,
      recomputedRootHash: recomputedRoot,
      certifiedAt: cert.rows[0].created_at,
      polygon_tx: cert.rows[0].polygon_tx,
      message: intact ? 'All fields verified — document is unaltered.' : 'TAMPER DETECTED — one or more fields do not match the certified values.'
    });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error.' });
  }
});

/* ---------------- DMS WEBHOOK (Dealer Management System sync) ---------------- */
// Drop this URL into any DMS (CDK, Reynolds & Reynolds, DealerSocket, Tekion) as a webhook.
// When a deal is finalized, the DMS posts the deal data here and we auto-certify it.
app.post("/api/v1/webhooks/dms", authenticateApiKey, async (req, res) => {
  try {
    const { vin, deal_number, buyer_name, sale_price, odometer, stock_number, sale_date, fields } = req.body;

    if (!vin && !deal_number) {
      return res.status(400).json({ error: 'At minimum, vin or deal_number is required.' });
    }

    // Build field set from whatever the DMS sends
    const dealFields = {
      vin:         vin || '',
      deal_number: deal_number || '',
      buyer_name:  buyer_name || '',
      sale_price:  String(sale_price || ''),
      odometer:    String(odometer || ''),
      stock_number:stock_number || '',
      sale_date:   sale_date || new Date().toISOString().split('T')[0],
      ...fields // allow DMS to pass extra fields
    };

    const proofId = 'PD-DMS-' + Date.now() + '-' + crypto.randomBytes(3).toString('hex');
    const timestamp = new Date().toISOString();

    const fieldHashes = {};
    for (const [key, value] of Object.entries(dealFields)) {
      fieldHashes[key] = crypto.createHash('sha256').update(String(value)).digest('hex');
    }
    const rootInput = Object.keys(fieldHashes).sort().map(k => `${k}:${fieldHashes[k]}`).join('|');
    const rootHash = crypto.createHash('sha256').update(rootInput).digest('hex');

    await pool.query(
      `INSERT INTO certifications (certification_id, hash, polygon_tx, api_key_email, ip_address, created_at)
       VALUES ($1, $2, NULL, $3, $4, NOW()) ON CONFLICT (certification_id) DO NOTHING`,
      [proofId, rootHash, req.apiKey.email, req.ip || req.headers['x-forwarded-for'] || null]
    );
    await pool.query(
      'UPDATE api_keys SET used_this_month = used_this_month + 1 WHERE api_key = $1',
      [req.apiKey.api_key]
    );
    if (req.apiKey.stripe_subscription_item_id) {
      await reportUsageToStripe(req.apiKey.stripe_subscription_item_id, 1);
    }

    const verifyUrl = `https://proofdeed.com/verify/${rootHash}`;

    res.json({
      proofId, timestamp, rootHash, fieldHashes, verifyUrl,
      vin: vin || null, deal_number: deal_number || null,
      message: `Deal ${deal_number || vin} certified. Share verifyUrl with buyer for public proof.`
    });

    console.log(`[DMS Webhook] Deal certified — VIN: ${vin || 'N/A'}, Deal: ${deal_number || 'N/A'}, ProofId: ${proofId}`);

    anchorToPolygon(rootHash).then(async (txHash) => {
      await pool.query('UPDATE certifications SET polygon_tx=$1 WHERE certification_id=$2', [txHash, proofId]);
      if (req.apiKey.webhook_url) {
        fetch(req.apiKey.webhook_url, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ event: 'dms.deal.certified', proofId, rootHash, verifyUrl, vin, deal_number, timestamp, polygon_tx: txHash })
        }).catch(() => {});
      }
    }).catch(err => console.error('DMS blockchain anchor failed:', err.message));

  } catch (err) {
    console.error('DMS webhook error:', err);
    res.status(500).json({ error: 'Internal server error.' });
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
            "This certificate is legally defensible under FRE Rule 901. Keep this email as your record.",
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
          const affiliateHtml = "<!DOCTYPE html><html><body style='margin:0;padding:0;background:#f0f0ee;font-family:Georgia,serif;'><div style='max-width:600px;margin:40px auto;background:#ffffff;border:1px solid #ddd;border-radius:4px;overflow:hidden;'><div style='height:4px;background:linear-gradient(90deg,#1a3a8e,#4080d0,#1a3a8e);'></div><div style='padding:40px;'><h1 style='font-size:22px;font-weight:700;color:#111;margin:0 0 8px;'>Welcome to ProofDeed Affiliates</h1><p style='font-size:14px;color:#666;margin:0 0 32px;'>Your affiliate account is ready. Start sharing your unique referral link below.</p><div style='background:#f8f8f6;border:1px solid #e5e5e5;border-radius:4px;padding:24px;margin-bottom:24px;'><p style='font-size:11px;font-weight:700;color:#999;text-transform:uppercase;letter-spacing:0.1em;margin:0 0 6px;'>Your Referral Code</p><p style='font-size:24px;font-family:monospace;color:#1a3a8e;font-weight:700;margin:0 0 20px;'>" + code + "</p><p style='font-size:11px;font-weight:700;color:#999;text-transform:uppercase;letter-spacing:0.1em;margin:0 0 6px;'>Your Referral Links</p><p style='font-size:13px;font-family:monospace;color:#333;margin:0 0 8px;'>https://proofdeed.com/auto?ref=" + code + "</p><p style='font-size:13px;font-family:monospace;color:#333;margin:0 0 8px;'>https://proofdeed.com/document?ref=" + code + "</p></div><p style='font-size:14px;color:#555;margin:0 0 16px;'>Every customer who signs up through your link will be tracked automatically.</p><p style='font-size:14px;color:#555;margin:0 0 32px;'>Questions? Contact us at <a href=\"mailto:info@proofdeed.com\" style=\"color:#1a3a8e;\">info@proofdeed.com</a></p><hr style='border:none;border-top:1px solid #e5e5e5;margin:24px 0;'><p style='font-size:12px;color:#999;font-family:sans-serif;margin:0;'>ProofDeed &mdash; Trust Infrastructure Platform</p></div><div style='height:4px;background:linear-gradient(90deg,#1a3a8e,#4080d0,#1a3a8e);'></div></div></body></html>";
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
          to: process.env.MAIL_TO || process.env.ADMIN_EMAIL || "SJJK@pm.me",
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

      const htmlProofEmail = "<!DOCTYPE html><html><body style='margin:0;padding:0;background:#f0f0ee;font-family:Georgia,serif;'><div style='max-width:600px;margin:40px auto;background:#ffffff;border:1px solid #ddd;border-radius:4px;overflow:hidden;'><div style='height:4px;background:linear-gradient(90deg,#1a3a8e,#4080d0,#1a3a8e);'></div><div style='padding:40px;'><h1 style='font-size:22px;font-weight:700;color:#111;margin:0 0 8px;'>Document Certified</h1><p style='font-size:14px;color:#666;margin:0 0 32px;'>Your document has been permanently recorded on the Polygon blockchain.</p><div style='background:#f8f8f6;border:1px solid #e5e5e5;border-radius:4px;padding:24px;margin-bottom:24px;'><p style='font-size:11px;font-weight:700;color:#999;text-transform:uppercase;letter-spacing:0.1em;margin:0 0 6px;'>Proof ID</p><p style='font-size:18px;font-family:monospace;color:#1a3a8e;font-weight:700;margin:0 0 20px;'>" + proofId + "</p><p style='font-size:11px;font-weight:700;color:#999;text-transform:uppercase;letter-spacing:0.1em;margin:0 0 6px;'>Document Hash</p><p style='font-size:11px;font-family:monospace;color:#333;word-break:break-all;margin:0 0 20px;'>" + documentHash + "</p><p style='font-size:11px;font-weight:700;color:#999;text-transform:uppercase;letter-spacing:0.1em;margin:0 0 6px;'>Timestamp</p><p style='font-size:13px;color:#333;margin:0;'>" + timestamp + "</p></div><a href='https://proofdeed.com/verify' style='display:inline-block;background:#0f172a;color:#ffffff;text-decoration:none;padding:14px 28px;border-radius:6px;font-family:sans-serif;font-size:14px;font-weight:600;margin-bottom:24px;'>Verify Certificate</a><hr style='border:none;border-top:1px solid #e5e5e5;margin:24px 0;'><p style='font-size:12px;color:#999;font-family:sans-serif;margin:0;'>ProofDeed &mdash; Trust Infrastructure Platform</p><p style='font-size:12px;color:#999;font-family:sans-serif;margin:4px 0 0;'><a href='https://proofdeed.com' style='color:#1a3a8e;'>proofdeed.com</a></p></div><div style='height:4px;background:linear-gradient(90deg,#1a3a8e,#4080d0,#1a3a8e);'></div></div></body></html>";

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
      "starter-monthly":       process.env.PRICE_STARTER_MONTHLY,
      "starter-annual":        process.env.PRICE_STARTER_YEARLY,
      "pro-monthly":           process.env.PRICE_PRO_MONTHLY,
      "pro-annual":            process.env.PRICE_PRO_YEARLY,
      "enterprise":            process.env.PRICE_ENTERPRISE,
      "professional-monthly":  process.env.PRICE_PROFESSIONAL_MONTHLY,
      "business-monthly":      process.env.PRICE_BUSINESS_MONTHLY,
      "enterprise-monthly":    process.env.PRICE_ENTERPRISE_MONTHLY,
      "government-monthly":    process.env.PRICE_GOVERNMENT_MONTHLY,
      "api-monthly":           process.env.PRICE_API_MONTHLY,
    };

    const oneTimePlans = {
      "government-pilot": process.env.PRICE_GOVERNMENT_PILOT,
    };

    const isOneTime = plan in oneTimePlans;
    const priceId = isOneTime ? oneTimePlans[plan] : subscriptionPlans[plan];
    if (!priceId) return res.status(400).json({ error: "Invalid plan: " + plan });

    const sessionParams = {
      mode: isOneTime ? "payment" : "subscription",
      ...(isOneTime ? {} : { payment_method_types: ["card"] }),
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: success_url || "https://proofdeed.com/success",
      cancel_url: cancel_url || "https://proofdeed.com",
      client_reference_id: referral ? referral : undefined,
      metadata: { plan },
    };

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
                "You have " + certLimit + " certifications per month. Every document you certify receives a permanent, permanently anchored to the Polygon blockchain.",
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

// Track referral click — set cookie and redirect to homepage
app.get('/ref/:code', async (req, res) => {
  const { code } = req.params;
  const aff = await pool.query('SELECT id FROM affiliates WHERE referral_code=$1 AND status=$2', [code, 'active']).catch(() => ({ rows: [] }));
  if (aff.rows.length) {
    res.cookie('pd_ref', code, { maxAge: 30 * 24 * 60 * 60 * 1000, httpOnly: false, sameSite: 'lax' });
    await pool.query('INSERT INTO affiliate_referrals (affiliate_id, referral_code, status) VALUES ($1,$2,$3)', [aff.rows[0].id, code, 'clicked']).catch(() => {});
  }
  res.redirect('https://proofdeed.com');
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
  const provided = req.headers["x-admin-secret"];
  // Accept ADMIN_PASSWORD (simple login password) or ADMIN_SECRET (API secret) — whichever is set
  const validPassword = process.env.ADMIN_PASSWORD || process.env.ADMIN_SECRET;
  if (provided !== validPassword) return false;

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
      ALTER TABLE outreach_contacts ADD COLUMN IF NOT EXISTS intent TEXT DEFAULT 'unknown';
      ALTER TABLE outreach_contacts ADD COLUMN IF NOT EXISTS sentiment TEXT DEFAULT 'neutral';
      ALTER TABLE outreach_contacts ADD COLUMN IF NOT EXISTS last_inbound_at TIMESTAMPTZ;
      ALTER TABLE outreach_contacts ADD COLUMN IF NOT EXISTS requires_human BOOLEAN DEFAULT false;
      ALTER TABLE outreach_contacts ADD COLUMN IF NOT EXISTS auto_replied BOOLEAN DEFAULT false;
      -- Fix existing contacts incorrectly flagged requires_human=true by the column default
      UPDATE outreach_contacts SET requires_human = false WHERE requires_human = true AND last_inbound_at IS NULL;

      -- Inbound email inbox (agent-ready)
      CREATE TABLE IF NOT EXISTS inbound_emails (
        id              SERIAL PRIMARY KEY,
        message_id      TEXT UNIQUE,
        thread_id       TEXT,
        contact_id      INTEGER REFERENCES outreach_contacts(id) ON DELETE SET NULL,
        from_email      TEXT NOT NULL,
        from_name       TEXT,
        to_email        TEXT,
        subject         TEXT,
        body_text       TEXT,
        body_html       TEXT,
        intent          TEXT DEFAULT 'unknown',
        sentiment       TEXT DEFAULT 'neutral',
        suggested_reply TEXT,
        auto_replied    BOOLEAN DEFAULT false,
        requires_human  BOOLEAN DEFAULT true,
        is_read         BOOLEAN DEFAULT false,
        received_at     TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_inbound_emails_contact ON inbound_emails(contact_id);
      CREATE INDEX IF NOT EXISTS idx_inbound_emails_from ON inbound_emails(from_email);
      CREATE INDEX IF NOT EXISTS idx_inbound_emails_thread ON inbound_emails(thread_id);
      CREATE INDEX IF NOT EXISTS idx_inbound_emails_received ON inbound_emails(received_at DESC);

      -- Affiliate tracking
      CREATE TABLE IF NOT EXISTS affiliates (
        id SERIAL PRIMARY KEY,
        contact_id INTEGER REFERENCES outreach_contacts(id) ON DELETE SET NULL,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        company TEXT,
        referral_code TEXT UNIQUE NOT NULL,
        commission_rate NUMERIC(5,2) DEFAULT 20.00,
        commission_type TEXT DEFAULT 'percentage',
        flat_amount NUMERIC(10,2),
        payout_method TEXT DEFAULT 'manual',
        payout_email TEXT,
        status TEXT DEFAULT 'active',
        notes TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      -- White-label columns for affiliates
      ALTER TABLE affiliates ADD COLUMN IF NOT EXISTS white_label_enabled BOOLEAN DEFAULT FALSE;
      ALTER TABLE affiliates ADD COLUMN IF NOT EXISTS brand_name TEXT;
      ALTER TABLE affiliates ADD COLUMN IF NOT EXISTS brand_logo_url TEXT;
      ALTER TABLE affiliates ADD COLUMN IF NOT EXISTS brand_color TEXT DEFAULT '#1a3a8e';
      ALTER TABLE affiliates ADD COLUMN IF NOT EXISTS brand_tagline TEXT;
      ALTER TABLE affiliates ADD COLUMN IF NOT EXISTS brand_website TEXT;

      CREATE TABLE IF NOT EXISTS affiliate_referrals (
        id SERIAL PRIMARY KEY,
        affiliate_id INTEGER REFERENCES affiliates(id) ON DELETE CASCADE,
        referred_email TEXT,
        referred_name TEXT,
        referred_company TEXT,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        referral_code TEXT,
        status TEXT DEFAULT 'clicked',
        plan TEXT,
        mrr NUMERIC(10,2) DEFAULT 0,
        commission_amount NUMERIC(10,2) DEFAULT 0,
        commission_status TEXT DEFAULT 'pending',
        converted_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS affiliate_payouts (
        id SERIAL PRIMARY KEY,
        affiliate_id INTEGER REFERENCES affiliates(id) ON DELETE CASCADE,
        amount NUMERIC(10,2) NOT NULL,
        payout_method TEXT DEFAULT 'manual',
        reference TEXT,
        status TEXT DEFAULT 'pending',
        notes TEXT,
        paid_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

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

      CREATE TABLE IF NOT EXISTS domain_reputation (
        domain         TEXT PRIMARY KEY,
        bounce_count   INT NOT NULL DEFAULT 0,
        deliver_count  INT NOT NULL DEFAULT 0,
        is_catch_all   BOOLEAN NOT NULL DEFAULT false,
        suppressed     BOOLEAN NOT NULL DEFAULT false,
        last_seen      TIMESTAMPTZ DEFAULT NOW()
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

/* ---------------- ONE-TIME: reset contacts sent from wrong domain ---------------- */
async function resetWrongDomainContacts() {
  try {
    const flagRow = await pool.query(`SELECT value FROM lead_engine_state WHERE key='domain_reset_done'`);
    if (flagRow.rows.length > 0 && flagRow.rows[0].value === 'true') return;
    const result = await pool.query(`
      DELETE FROM outreach_contacts
      WHERE status IN ('sent','delivered','opened')
      AND status NOT IN ('bounced','suppressed','complained','unsubscribed','replied','in_talks','closed_won','closed_lost')
    `);
    await pool.query(`INSERT INTO lead_engine_state (key,value,updated_at) VALUES ('domain_reset_done','true',NOW()) ON CONFLICT (key) DO UPDATE SET value='true',updated_at=NOW()`);
    console.log(`[DomainReset] Cleared ${result.rowCount} contacts for re-outreach from correct domain.`);
  } catch(err) {
    console.error('[DomainReset] Error:', err.message);
  }
}
resetWrongDomainContacts();

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

/* ---------------- DAILY SYSTEM HEALTH CHECK ---------------- */
// Runs daily at 13:00 UTC (8am CT) — checks DB, auth, Stripe, Resend; emails alert on failure
cron.schedule("0 13 * * *", async () => {
  const checks = [];
  let failed = false;

  // 1. Database
  try {
    await pool.query("SELECT NOW()");
    checks.push("✅ Database: OK");
  } catch (e) {
    checks.push(`❌ Database: FAILED — ${e.message}`);
    failed = true;
  }

  // 2. Auth (JWT + magic_links table)
  try {
    await pool.query("SELECT COUNT(*) FROM magic_links WHERE expires_at > NOW()");
    const tok = jwt.sign({ health: true }, process.env.JWT_SECRET, { expiresIn: "1m" });
    jwt.verify(tok, process.env.JWT_SECRET);
    checks.push("✅ Auth / JWT: OK");
  } catch (e) {
    checks.push(`❌ Auth / JWT: FAILED — ${e.message}`);
    failed = true;
  }

  // 3. Stripe
  try {
    const Stripe = (await import("stripe")).default;
    const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
    await stripe.balance.retrieve();
    checks.push("✅ Stripe: OK");
  } catch (e) {
    checks.push(`❌ Stripe: FAILED — ${e.message}`);
    failed = true;
  }

  // 4. Resend API
  try {
    const r = await resend.domains.list();
    if (!r || r.error) throw new Error(r?.error?.message || "no response");
    checks.push("✅ Resend API: OK");
  } catch (e) {
    checks.push(`❌ Resend API: FAILED — ${e.message}`);
    failed = true;
  }

  // 5. MX records — verify inbound.resend.com is set (not a dead provider)
  try {
    const { promises: dns } = await import('dns');
    const mx = await dns.resolveMx('proofdeed.com');
    const hasResend = mx.some(r => r.exchange.includes('resend'));
    const hasZoho = mx.some(r => r.exchange.includes('zoho'));
    const hasOldProvider = mx.some(r => r.exchange.includes('zoho') || r.exchange.includes('google') || r.exchange.includes('outlook'));
    if (!hasResend) throw new Error(`MX not pointing to Resend — found: ${mx.map(r=>r.exchange).join(', ')}`);
    if (hasOldProvider) throw new Error(`Old MX still present: ${mx.filter(r=>hasOldProvider).map(r=>r.exchange).join(', ')}`);
    checks.push(`✅ MX Records: inbound.resend.com (priority ${mx.find(r=>r.exchange.includes('resend'))?.priority})`);
  } catch (e) {
    checks.push(`❌ MX Records: FAILED — ${e.message}`);
    failed = true;
  }

  // 6. Resend domain receiving enabled
  try {
    const domainRes = await fetch('https://api.resend.com/domains/3e78f4d1-e142-4156-9bb1-cc3ef5039cbe', {
      headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}` }
    });
    const domain = await domainRes.json();
    if (domain.capabilities?.receiving !== 'enabled') throw new Error(`receiving is ${domain.capabilities?.receiving}`);
    checks.push("✅ Resend Inbound Receiving: enabled");
  } catch (e) {
    checks.push(`❌ Resend Inbound Receiving: FAILED — ${e.message}`);
    failed = true;
  }

  // 7. Lead engine — self-healing check: auto-reset stuck flag + auto-restart if stalled
  try {
    // Auto-reset stuck is_running flag
    const leRow = await pool.query(`SELECT value, updated_at FROM lead_engine_state WHERE key='is_running'`).catch(() => ({ rows: [] }));
    if (leRow.rows[0]?.value === 'true') {
      const stuckHours = leRow.rows[0]?.updated_at
        ? (Date.now() - new Date(leRow.rows[0].updated_at).getTime()) / 3600000
        : 99;
      if (stuckHours >= 3) {
        await pool.query(`INSERT INTO lead_engine_state (key,value,updated_at) VALUES ('is_running','false',NOW()) ON CONFLICT (key) DO UPDATE SET value='false',updated_at=NOW()`).catch(() => {});
        console.log(`[health-check] Auto-reset stuck is_running (stuck ${stuckHours.toFixed(1)}h)`);
      }
    }

    // Check recent send volume
    const sent = await pool.query(`SELECT COUNT(*) FROM outreach_contacts WHERE first_sent_at >= NOW() - INTERVAL '25 hours'`);
    const count = parseInt(sent.rows[0].count);
    const day = new Date().getDay();
    const isWeekday = day >= 1 && day <= 5;

    if (isWeekday && count === 0) {
      // Auto-restart the engine
      runLeadEngine(200).catch(() => {});
      throw new Error(`No new outreach in 25h — auto-restarted engine. Check DO logs.`);
    }
    checks.push(`✅ Lead Engine: ${count} new contacts in last 25h`);
  } catch (e) {
    checks.push(`❌ Lead Engine: ${e.message}`);
    failed = true;
  }

  const status = failed ? "🚨 ALERT — ProofDeed System Failure" : "✅ ProofDeed Daily Health Check — All Systems OK";
  const body = checks.join("\n");

  console.log(`[health-check] ${status}\n${body}`);

  if (failed) {
    try {
      await resend.emails.send({
        from: "ProofDeed System <info@proofdeed.com>",
        to: "sjjk@pm.me",
        subject: status,
        text: `ProofDeed daily health check results:\n\n${body}\n\nTime: ${new Date().toISOString()}\n\nLog in to DigitalOcean to investigate: https://cloud.digitalocean.com/apps/753587e4-5e82-46af-a29e-a80b7dd60f87`,
      });
    } catch (emailErr) {
      console.error("[health-check] Failed to send alert email:", emailErr.message);
    }
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

    // Auto-suppress hard bounces and complaints — protects sending reputation
    if (newStatus === 'bounced' && metadata.bounce_type === 'hard') {
      await pool.query(
        `UPDATE outreach_contacts SET status='bounced', pipeline_stage='suppressed', suppressed_at=NOW(), suppressed_reason='hard_bounce' WHERE id=$1`,
        [contact.id]
      );
      await recordEmailEvent(contact.email, 'bounce');
      console.log(`[Resend Webhook] Hard bounce suppressed: ${contact.email}`);
    } else if (newStatus === 'bounced') {
      await recordEmailEvent(contact.email, 'bounce');
    }
    if (newStatus === 'delivered') {
      await recordEmailEvent(contact.email, 'deliver');
    }
    if (newStatus === 'complained') {
      await pool.query(
        `UPDATE outreach_contacts SET status='complained', pipeline_stage='suppressed', suppressed_at=NOW(), suppressed_reason='spam_complaint' WHERE id=$1`,
        [contact.id]
      );
      console.log(`[Resend Webhook] Spam complaint suppressed: ${contact.email}`);
    }
  } catch (err) {
    console.error('Resend webhook error:', err.message);
  }
});

// ---------- Resend INBOUND webhook (reply detection + inbox catch-all) ----------
app.post(['/api/webhooks/resend-inbound', '/webhooks/resend-inbound'], async (req, res) => {
  res.status(200).json({ received: true });
  try {
    if (process.env.RESEND_INBOUND_SECRET && req.query.secret !== process.env.RESEND_INBOUND_SECRET) return;

    const raw = req.body || {};
    // Resend inbound wraps in event.type + event.data for email.received
    const body = (raw.type === 'email.received' && raw.data) ? raw.data : raw;
    const toField   = Array.isArray(body.to) ? body.to.join(',') : (body.to || body.To || '');
    const fromField = body.from || body.From || '';
    const subject   = body.subject || body.Subject || '(no subject)';
    const bodyText  = body.text || body.Text || '';
    const messageId = body.headers?.['message-id'] || body.messageId || `rs-${Date.now()}`;
    const inReplyTo = body.headers?.['in-reply-to'] || null;

    // ── Path 1: reply+tag (outbound follow-up reply) ──
    const match = toField.match(/reply\+([^@\s<>]+)@(?:send\.)?proofdeed\.com/i);
    if (!match) {
      // ── Path 2: direct inbox email (info@ or gov@) ──
      const isInbox = /info@proofdeed\.com|gov@proofdeed\.com/i.test(toField);
      if (!isInbox) return;

      const fromEmail = (fromField.match(/<([^>]+)>/) || [, fromField])[1].trim().toLowerCase();
      const fromName  = (fromField.match(/^([^<]+)</) || [,''])[1].trim().replace(/^"|"$/g,'') || fromEmail;
      const toEmail   = toField.toLowerCase().includes('gov') ? 'gov@proofdeed.com' : 'info@proofdeed.com';
      const ourDomains = ['proofdeed.com', 'send.proofdeed.com'];
      if (ourDomains.some(d => fromEmail.endsWith(d))) return;

      const fullText = (subject + ' ' + bodyText).toLowerCase();
      const intent = ['interested','pricing','pilot','demo','schedule','call'].some(k => fullText.includes(k)) ? 'pricing_inquiry'
                   : ['not working','error','issue','help','support'].some(k => fullText.includes(k))         ? 'support'
                   : ['partner','integrate','resell','api'].some(k => fullText.includes(k))                   ? 'partnership'
                   : 'inquiry';
      const sentiment = ['not interested','unsubscribe','stop','spam'].some(k => fullText.includes(k)) ? 'negative'
                      : ['great','love','perfect','impressed','interested'].some(k => fullText.includes(k)) ? 'positive'
                      : 'neutral';
      const threadId = inReplyTo || messageId;

      // Find or create contact
      const emailDomain = fromEmail.split('@')[1] || '';
      const companyGuess = emailDomain.replace(/\.(com|gov|org|net|edu|io)$/,'').replace(/[-_]/g,' ').replace(/\b\w/g,c=>c.toUpperCase());
      const upsert = await pool.query(`
        INSERT INTO outreach_contacts (name,email,company,pipeline_stage,pain_status,intent,sentiment,status,last_inbound_at,requires_human,created_at)
        VALUES ($1,$2,$3,'replied','aware',$4,$5,'replied',NOW(),true,NOW())
        ON CONFLICT (email) DO UPDATE SET last_inbound_at=NOW(),intent=$4,sentiment=$5,
          pipeline_stage=CASE WHEN outreach_contacts.pipeline_stage IN ('targeted','contacted') THEN 'replied' ELSE outreach_contacts.pipeline_stage END,
          pain_status=CASE WHEN outreach_contacts.pain_status='unaware' THEN 'aware' ELSE outreach_contacts.pain_status END,
          status=CASE WHEN outreach_contacts.status NOT IN ('replied','in_talks','closed_won') THEN 'replied' ELSE outreach_contacts.status END
        RETURNING *
      `, [fromName, fromEmail, companyGuess, intent, sentiment]);
      const contact = upsert.rows[0];

      await pool.query(`
        INSERT INTO inbound_emails (message_id,thread_id,contact_id,from_email,from_name,to_email,subject,body_text,intent,sentiment,requires_human,received_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,true,NOW()) ON CONFLICT (message_id) DO NOTHING
      `, [messageId, threadId, contact.id, fromEmail, fromName, toEmail, subject, bodyText.substring(0,10000), intent, sentiment]);

      await pool.query(`INSERT INTO outreach_events (contact_id,event_type,event_source,metadata,occurred_at) VALUES ($1,'replied','resend_inbound',$2,NOW())`,
        [contact.id, JSON.stringify({ from: fromEmail, subject, snippet: bodyText.substring(0,200), intent })]);

      // Forward to ProtonMail so Scott sees it in his inbox
      const { Resend: ResendFwd } = await import('resend');
      const resendFwd = new ResendFwd(process.env.RESEND_API_KEY);
      await resendFwd.emails.send({
        from: `${fromName} via ProofDeed <info@proofdeed.com>`,
        to: 'sjjk@pm.me',
        reply_to: fromEmail,
        subject: subject,
        text: `From: ${fromField}\nTo: ${toField}\n\n${bodyText}`,
      }).catch(() => {});

      console.log(`📥 Inbox email: ${fromEmail} → ${toEmail} | ${intent} — forwarded to ProtonMail`);
      return;
    }

    const tag = match[1];
    const r = await pool.query('SELECT * FROM outreach_contacts WHERE reply_to_tag=$1', [tag]);
    const contact = r.rows[0];
    if (!contact) return;

    const textSnippet = bodyText.substring(0, 500);

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

    // Forward to ProtonMail so Scott sees the reply
    const { Resend: ResendReply } = await import('resend');
    const resendReply = new ResendReply(process.env.RESEND_API_KEY);
    await resendReply.emails.send({
      from: `${contact.name} via ProofDeed <info@proofdeed.com>`,
      to: 'sjjk@pm.me',
      reply_to: contact.email,
      subject: `Re: ${subject}`,
      text: `From: ${fromField}\nCompany: ${contact.company}\nIntent: ${isHighIntent ? '🔥 HIGH' : 'standard'}\n\n${textSnippet}`,
    }).catch(() => {});

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

// ---------- Mailgun INBOUND webhook (info@ / gov@ catch-all) ----------
app.post(['/api/webhooks/mailgun-inbound', '/webhooks/mailgun-inbound'], async (req, res) => {
  res.status(200).json({ received: true }); // always ack immediately

  try {
    const body = req.body || {};

    const fromRaw   = body.from    || body.From    || body.sender || '';
    const toRaw     = body.to      || body.To      || body.recipient || '';
    const subject   = body.subject || body.Subject || '(no subject)';
    const bodyText  = body['body-plain']  || body.text || body.Text || '';
    const bodyHtml  = body['body-html']   || body.html || body.Html || '';
    const messageId = body['Message-Id']  || body['message-id'] || body.messageId || `mg-${Date.now()}`;
    const inReplyTo = body['In-Reply-To'] || body['in-reply-to'] || null;

    // Parse "Name <email>" format
    const fromEmail = (fromRaw.match(/<([^>]+)>/) || [, fromRaw])[1].trim().toLowerCase();
    const fromName  = (fromRaw.match(/^([^<]+)</) || [,''])[1].trim().replace(/^"|"$/g,'') || fromEmail;
    const toEmail   = (toRaw.match(/<([^>]+)>/)   || [, toRaw])[1].trim().toLowerCase();

    // Skip if it's our own sends bouncing back
    const ourDomains = ['proofdeed.com', 'send.proofdeed.com'];
    if (ourDomains.some(d => fromEmail.endsWith(d))) return;

    // Basic intent classification (keyword-based — AI slot for later)
    const fullText = (subject + ' ' + bodyText).toLowerCase();
    const highIntentKeywords = ['interested','learn more','tell me more','details','schedule','call','demo','pricing','pilot','sounds good','set up','how does','let\'s talk'];
    const supportKeywords    = ['not working','broken','error','issue','problem','help','support','bug','fix'];
    const partnerKeywords    = ['partner','partnership','integrate','api','resell','white label','collaborate'];
    const intent = highIntentKeywords.some(k => fullText.includes(k)) ? 'pricing_inquiry'
                 : supportKeywords.some(k => fullText.includes(k))    ? 'support'
                 : partnerKeywords.some(k => fullText.includes(k))    ? 'partnership'
                 : 'inquiry';

    const positiveWords = ['great','excellent','love','perfect','awesome','impressive','interested'];
    const negativeWords = ['not interested','unsubscribe','remove','stop','no thanks','spam'];
    const sentiment = negativeWords.some(k => fullText.includes(k)) ? 'negative'
                    : positiveWords.some(k => fullText.includes(k)) ? 'positive'
                    : 'neutral';

    // Use In-Reply-To as thread_id, else message_id starts a new thread
    const threadId = inReplyTo || messageId;

    // Find or create contact
    let contact = (await pool.query('SELECT * FROM outreach_contacts WHERE email=$1', [fromEmail])).rows[0];
    if (!contact) {
      // Parse company from email domain
      const emailDomain = fromEmail.split('@')[1] || '';
      const companyGuess = emailDomain.replace(/\.(com|gov|org|net|edu|io)$/, '').replace(/[-_]/g, ' ')
        .replace(/\b\w/g, c => c.toUpperCase());

      const ins = await pool.query(`
        INSERT INTO outreach_contacts
          (name, email, company, pipeline_stage, pain_status, intent, sentiment, status, last_inbound_at, requires_human, created_at)
        VALUES ($1,$2,$3,'replied','aware',$4,$5,'replied',NOW(),true,NOW())
        ON CONFLICT (email) DO UPDATE
          SET last_inbound_at=NOW(), intent=$4, sentiment=$5, pipeline_stage='replied', pain_status='aware'
        RETURNING *
      `, [fromName, fromEmail, companyGuess, intent, sentiment]);
      contact = ins.rows[0];
    } else {
      // Update existing contact with new intel
      await pool.query(`
        UPDATE outreach_contacts
        SET last_inbound_at=NOW(), intent=$1, sentiment=$2,
            pipeline_stage = CASE WHEN pipeline_stage IN ('targeted','contacted') THEN 'replied' ELSE pipeline_stage END,
            pain_status    = CASE WHEN pain_status = 'unaware' THEN 'aware' ELSE pain_status END,
            status         = CASE WHEN status NOT IN ('replied','in_talks','closed_won') THEN 'replied' ELSE status END
        WHERE id=$3
      `, [intent, sentiment, contact.id]);
    }

    // Store the email
    await pool.query(`
      INSERT INTO inbound_emails
        (message_id, thread_id, contact_id, from_email, from_name, to_email, subject, body_text, body_html, intent, sentiment, requires_human, received_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,true,NOW())
      ON CONFLICT (message_id) DO NOTHING
    `, [messageId, threadId, contact.id, fromEmail, fromName, toEmail, subject,
        bodyText.substring(0, 10000), bodyHtml.substring(0, 50000), intent, sentiment]);

    // Log event on contact timeline
    await pool.query(`
      INSERT INTO outreach_events (contact_id, event_type, event_source, metadata, occurred_at)
      VALUES ($1,'replied','mailgun_inbound',$2,NOW())
    `, [contact.id, JSON.stringify({ from: fromEmail, subject, snippet: bodyText.substring(0, 300), intent, sentiment })]);

    console.log(`📥 Inbound email: ${fromEmail} → ${toEmail} | intent: ${intent} | sentiment: ${sentiment}`);

    // Admin notification for anything that needs attention
    const mailgunDomain = process.env.MAILGUN_DOMAIN;
    const mailgunApiKey = process.env.MAILGUN_API_KEY;
    if (mailgunDomain && mailgunApiKey && sentiment !== 'negative') {
      const isHot = intent === 'pricing_inquiry' || intent === 'partnership';
      fetch('https://api.mailgun.net/v3/' + mailgunDomain + '/messages', {
        method: 'POST',
        headers: {
          'Authorization': 'Basic ' + Buffer.from('api:' + mailgunApiKey).toString('base64'),
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          from: process.env.MAIL_FROM || `ProofDeed CRM <mailgun@${mailgunDomain}>`,
          to: process.env.MAIL_TO || 'info@proofdeed.com',
          subject: `${isHot ? '🔥' : '📥'} New email: ${fromName} — ${subject}`,
          text: `New inbound email in CRM\n\nFrom: ${fromName} <${fromEmail}>\nTo: ${toEmail}\nSubject: ${subject}\nIntent: ${intent}\nSentiment: ${sentiment}\n\n---\n${bodyText.substring(0, 800)}\n\n---\nView in CRM: https://proofdeed.com/admin`
        })
      }).catch(() => {});
    }

  } catch (err) {
    console.error('Mailgun inbound webhook error:', err.message);
  }
});

// ---------- Admin: Outreach Stats ----------
// Domain reputation viewer
app.get(['/api/admin/domain-reputation', '/admin/domain-reputation'], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: 'Unauthorized.' });
  try {
    const suppressed = await pool.query(`SELECT domain, bounce_count, deliver_count, last_seen FROM domain_reputation WHERE suppressed=true ORDER BY bounce_count DESC LIMIT 100`);
    const risky = await pool.query(`SELECT domain, bounce_count, deliver_count, is_catch_all, last_seen FROM domain_reputation WHERE suppressed=false AND bounce_count > 0 ORDER BY bounce_count DESC LIMIT 100`);
    const totals = await pool.query(`SELECT COUNT(*) as total, SUM(bounce_count) as bounces, SUM(deliver_count) as delivers FROM domain_reputation`);
    res.json({ totals: totals.rows[0], suppressed: suppressed.rows, risky: risky.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Seed domain_reputation from existing bounce history in outreach_contacts
app.post(['/api/admin/domain-reputation/seed', '/admin/domain-reputation/seed'], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: 'Unauthorized.' });
  try {
    // Aggregate existing bounces by domain
    const bounces = await pool.query(`
      SELECT split_part(email,'@',2) AS domain, COUNT(*) AS bounce_count
      FROM outreach_contacts WHERE status IN ('bounced','hard_bounce')
      GROUP BY domain HAVING COUNT(*) > 0
    `);
    const delivers = await pool.query(`
      SELECT split_part(email,'@',2) AS domain, COUNT(*) AS deliver_count
      FROM outreach_contacts WHERE status IN ('delivered','opened','clicked','replied')
      GROUP BY domain HAVING COUNT(*) > 0
    `);
    const deliverMap = {};
    delivers.rows.forEach(r => { deliverMap[r.domain] = parseInt(r.deliver_count); });

    let seeded = 0, suppressed = 0;
    for (const row of bounces.rows) {
      const domain = row.domain;
      const bounceCount = parseInt(row.bounce_count);
      const deliverCount = deliverMap[domain] || 0;
      const total = bounceCount + deliverCount;
      const shouldSuppress = (bounceCount >= 2 && deliverCount === 0) ||
                             (total >= 4 && (bounceCount / total) >= 0.4);
      await pool.query(`
        INSERT INTO domain_reputation (domain, bounce_count, deliver_count, suppressed, last_seen)
        VALUES ($1, $2, $3, $4, NOW())
        ON CONFLICT (domain) DO UPDATE SET
          bounce_count = EXCLUDED.bounce_count,
          deliver_count = EXCLUDED.deliver_count,
          suppressed = EXCLUDED.suppressed,
          last_seen = NOW()
      `, [domain, bounceCount, deliverCount, shouldSuppress]);
      seeded++;
      if (shouldSuppress) suppressed++;
    }
    res.json({ seeded, suppressed, message: `Seeded ${seeded} domains, suppressed ${suppressed} high-bounce domains.` });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

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

// ---------- Public: Reseller / White-Label Signup ----------
app.post('/api/reseller/apply', authRateLimit, async (req, res) => {
  try {
    const { name, email, company, industry, website, plan, brand_name, brand_color, brand_tagline } = req.body;
    if (!name || !email || !company || !plan) return res.status(400).json({ error: 'name, email, company, and plan are required.' });

    const referral_code = crypto.randomBytes(4).toString('hex');
    const portal_url = `https://proofdeed.com/api/partner/${referral_code}`;
    const planLabels = { starter: 'Starter — $49/mo', pro: 'Pro — $149/mo', enterprise: 'Enterprise — Custom' };

    // Insert affiliate with white-label enabled
    let aff;
    try {
      const result = await pool.query(
        `INSERT INTO affiliates (name, email, company, referral_code, commission_type, payout_method, status,
          white_label_enabled, brand_name, brand_logo_url, brand_color, brand_tagline, brand_website, notes)
         VALUES ($1,$2,$3,$4,'flat','manual','pending',true,$5,null,$6,$7,$8,$9) RETURNING *`,
        [name, email.toLowerCase(), company, referral_code,
         brand_name || company, brand_color || '#1a3a8e', brand_tagline || null,
         website || null, `Reseller plan: ${plan}. Industry: ${industry || 'N/A'}`]
      );
      aff = result.rows[0];
    } catch (e) {
      if (e.code === '23505') return res.status(409).json({ error: 'An account with this email already exists.' });
      throw e;
    }

    const domain = process.env.MAILGUN_DOMAIN;
    const key = process.env.MAILGUN_API_KEY;

    // Welcome email to reseller
    if (domain && key) {
      await fetch(`https://api.mailgun.net/v3/${domain}/messages`, {
        method: 'POST',
        headers: { Authorization: 'Basic ' + Buffer.from('api:' + key).toString('base64'), 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          from: process.env.MAIL_FROM || `ProofDeed <noreply@${domain}>`,
          to: email,
          subject: `Welcome to ProofDeed Reseller — Your Portal Is Being Set Up`,
          text: `Hi ${name},\n\nThank you for applying to become a ProofDeed Reseller.\n\nYour branded portal is being configured and will be live within 24 hours at:\n\n${portal_url}\n\nPlan selected: ${planLabels[plan] || plan}\n\nWe will send your payment instructions to this email address within 24 hours. Once payment is confirmed, your portal will be activated and your clients can begin using it immediately.\n\nYour referral code: ${referral_code}\n\nIf you have any questions, reply to this email or contact us at info@proofdeed.com.\n\nProofDeed\nhttps://proofdeed.com`,
        }),
      }).catch(() => {});

      // Admin notification
      await sendAlertEmail(
        `🏪 New Reseller Application — ${company} (${plan})`,
        `New reseller signup:\n\nName: ${name}\nEmail: ${email}\nCompany: ${company}\nIndustry: ${industry || 'N/A'}\nPlan: ${planLabels[plan] || plan}\nWebsite: ${website || 'N/A'}\nBrand Name: ${brand_name || 'N/A'}\nBrand Color: ${brand_color || 'N/A'}\nTagline: ${brand_tagline || 'N/A'}\n\nPortal URL: ${portal_url}\nAffiliate ID: ${aff.id}\n\nAction needed: Send payment link and activate account in admin.\nhttps://proofdeed.com/admin`
      ).catch(() => {});
    }

    res.json({ success: true, referral_code, portal_url });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ---------- Admin: Export contacts as CSV ----------
app.get(['/api/admin/outreach/export-csv', '/admin/outreach/export-csv'], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: 'Unauthorized.' });
  try {
    const { status } = req.query; // optional filter e.g. ?status=sent
    let query = `SELECT name, email, company, title, industry, state, status, first_sent_at FROM outreach_contacts WHERE email IS NOT NULL AND email != ''`;
    const params = [];
    if (status) { params.push(status); query += ` AND status=$${params.length}`; }
    query += ` ORDER BY created_at DESC`;
    const result = await pool.query(query, params);
    const rows = result.rows;
    const header = ['First Name','Last Name','Email','Company','Title','Industry','State','Status','First Contact'];
    const lines = [header.join(',')];
    for (const r of rows) {
      const parts = (r.name || '').trim().split(/\s+/);
      const first = parts[0] || '';
      const last = parts.slice(1).join(' ') || '';
      const esc = (v) => `"${(v||'').replace(/"/g,'""')}"`;
      lines.push([esc(first),esc(last),esc(r.email),esc(r.company),esc(r.title),esc(r.industry),esc(r.state),esc(r.status),esc(r.first_sent_at)].join(','));
    }
    res.setHeader('Content-Type','text/csv');
    res.setHeader('Content-Disposition','attachment; filename="proofdeed-leads.csv"');
    res.send(lines.join('\n'));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ---------- Admin: Inbox (inbound emails) ----------
app.get(['/api/admin/inbox', '/admin/inbox'], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: 'Unauthorized.' });
  try {
    const page  = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(100, parseInt(req.query.limit) || 25);
    const offset = (page - 1) * limit;
    const unreadOnly = req.query.unread === '1';
    const intentFilter = req.query.intent || '';

    const conditions = [];
    const params = [];
    if (unreadOnly) conditions.push('i.is_read = false');
    if (intentFilter) { params.push(intentFilter); conditions.push(`i.intent = $${params.length}`); }
    const whereClause = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

    const result = await pool.query(`
      SELECT i.*,
        c.name  AS contact_name,
        c.company AS contact_company,
        c.pipeline_stage,
        c.priority_score
      FROM inbound_emails i
      LEFT JOIN outreach_contacts c ON c.id = i.contact_id
      ${whereClause}
      ORDER BY i.received_at DESC
      LIMIT $${params.length + 1} OFFSET $${params.length + 2}
    `, [...params, limit, offset]);

    const countResult = await pool.query(
      `SELECT COUNT(*) as total FROM inbound_emails i ${whereClause}`, params
    );
    const unreadCount = await pool.query(`SELECT COUNT(*) as total FROM inbound_emails WHERE is_read=false`);

    res.json({
      emails: result.rows,
      total: parseInt(countResult.rows[0].total),
      unread: parseInt(unreadCount.rows[0].total),
      page, limit
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ---------- Admin: Mark email read ----------
app.put(['/api/admin/inbox/:id/read', '/admin/inbox/:id/read'], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: 'Unauthorized.' });
  try {
    await pool.query('UPDATE inbound_emails SET is_read=true WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ---------- Admin: Get email thread ----------
app.get(['/api/admin/inbox/thread/:threadId', '/admin/inbox/thread/:threadId'], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: 'Unauthorized.' });
  try {
    const emails = await pool.query(
      `SELECT i.*, c.name AS contact_name, c.company AS contact_company
       FROM inbound_emails i LEFT JOIN outreach_contacts c ON c.id = i.contact_id
       WHERE i.thread_id = $1 ORDER BY i.received_at ASC`,
      [req.params.threadId]
    );
    res.json({ emails: emails.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ---------- Admin: Reply to inbound email ----------
app.post(['/api/admin/inbox/:id/reply', '/admin/inbox/:id/reply'], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: 'Unauthorized.' });
  try {
    const email = (await pool.query('SELECT * FROM inbound_emails WHERE id=$1', [req.params.id])).rows[0];
    if (!email) return res.status(404).json({ error: 'Email not found.' });

    const { body, subject } = req.body;
    if (!body) return res.status(400).json({ error: 'Reply body required.' });

    const mailgunDomain = process.env.MAILGUN_DOMAIN;
    const mailgunApiKey = process.env.MAILGUN_API_KEY;
    if (!mailgunDomain || !mailgunApiKey) return res.status(500).json({ error: 'Mailgun not configured.' });

    const replySubject = subject || (email.subject.startsWith('Re:') ? email.subject : `Re: ${email.subject}`);

    const mgRes = await fetch('https://api.mailgun.net/v3/' + mailgunDomain + '/messages', {
      method: 'POST',
      headers: {
        'Authorization': 'Basic ' + Buffer.from('api:' + mailgunApiKey).toString('base64'),
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        from: process.env.MAIL_FROM || `ProofDeed <info@${mailgunDomain}>`,
        to: email.from_email,
        subject: replySubject,
        text: body,
        'h:In-Reply-To': email.message_id,
        'h:References': email.message_id,
      })
    });

    if (!mgRes.ok) {
      const errText = await mgRes.text();
      return res.status(500).json({ error: 'Mailgun send failed: ' + errText });
    }

    // Mark email read, log event on contact
    await pool.query('UPDATE inbound_emails SET is_read=true WHERE id=$1', [email.id]);
    if (email.contact_id) {
      await pool.query(`
        INSERT INTO outreach_events (contact_id, event_type, event_source, metadata, occurred_at)
        VALUES ($1,'sent','admin_reply',$2,NOW())
      `, [email.contact_id, JSON.stringify({ to: email.from_email, subject: replySubject, snippet: body.substring(0, 200) })]);
      await pool.query(`
        UPDATE outreach_contacts SET last_contact_at=NOW(),
          pipeline_stage = CASE WHEN pipeline_stage = 'replied' THEN 'qualified' ELSE pipeline_stage END
        WHERE id=$1
      `, [email.contact_id]);
    }

    console.log(`✅ Admin replied to ${email.from_email} re: "${replySubject}"`);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ---------------- ADMIN: CSV IMPORT (Apollo.io) ---------------- */
app.post(['/api/admin/import/csv', '/admin/import/csv'], authRateLimit, upload.single('file'), async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: 'Unauthorized.' });
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded.' });

    const csv = req.file.buffer.toString('utf8');
    const lines = csv.split('\n').map(l => l.trim()).filter(Boolean);
    if (lines.length < 2) return res.status(400).json({ error: 'CSV appears empty.' });

    // Parse headers — normalize to lowercase, strip quotes
    const headers = lines[0].split(',').map(h => h.replace(/^"|"$/g, '').trim().toLowerCase().replace(/\s+/g, '_'));

    // Apollo column name mappings → our field names
    const colMap = {
      // Name
      first_name: 'first_name', last_name: 'last_name', full_name: 'name',
      'first name': 'first_name', 'last name': 'last_name',
      // Title
      title: 'title', job_title: 'title', 'job title': 'title',
      // Company
      company: 'company', organization: 'company', company_name: 'company', account_name: 'company',
      // Email
      email: 'email', 'work_email': 'email', 'email_address': 'email',
      // Industry
      industry: 'industry', 'company_industry': 'industry',
      // LinkedIn
      linkedin_url: 'linkedin', 'person_linkedin_url': 'linkedin',
      // Phone
      phone: 'phone', direct_phone_number: 'phone',
      // Location
      city: 'city', state: 'state', country: 'country',
      // Company size
      employees: 'company_size', num_employees: 'company_size', 'number_of_employees': 'company_size',
    };

    const getField = (row, ...keys) => {
      for (const key of keys) {
        const idx = headers.indexOf(key);
        if (idx !== -1 && row[idx]) return row[idx].replace(/^"|"$/g, '').trim();
      }
      return '';
    };

    // Determine industry from Apollo industry string
    const mapIndustry = (apolloIndustry) => {
      const s = (apolloIndustry || '').toLowerCase();
      if (s.includes('proptech') || s.includes('real estate services') || s.includes('real estate investment') || s.includes('reit') || s.includes('real estate technology')) return 'real_estate';
      if (s.includes('title insurance') || s.includes('title company') || s.includes('title & escrow') || s.includes('escrow')) return 'title_escrow';
      if (s.includes('real estate') || s.includes('property')) return 'title_escrow';
      if (s.includes('government regulator') || s.includes('regulatory authority') || s.includes('tax authority') || s.includes('financial regulator') || s.includes('law enforcement') || s.includes('central bank') || s.includes('audit institution') || s.includes('anti-fraud') || s.includes('anti-corruption')) return 'gov_regulator';
      if (s.includes('government') || s.includes('public') || s.includes('municipal')) return 'government';
      if (s.includes('pharma') || s.includes('biotech') || s.includes('life science')) return 'pharma';
      if (s.includes('aviation') || s.includes('aerospace') || s.includes('airline')) return 'aviation';
      if (s.includes('automotive') || s.includes('auto') || s.includes('vehicle')) return 'auto';
      if (s.includes('financial') || s.includes('private equity') || s.includes('investment') || s.includes('banking')) return 'institutional';
      if (s.includes('insurance')) return 'insurance';
      if (s.includes('legal') || s.includes('law')) return 'legal';
      if (s.includes('construction')) return 'construction';
      if (s.includes('hospital') || s.includes('health') || s.includes('medical')) return 'healthcare';
      if (s.includes('higher education') || s.includes('research institution') || s.includes('research university')) return 'university_research';
      if (s.includes('education') || s.includes('university') || s.includes('college') || s.includes('credentialing') || s.includes('licensing board')) return 'education';
      if (s.includes('logistics') || s.includes('freight') || s.includes('transportation') || s.includes('supply chain')) return 'supply_chain';
      if (s.includes('blockchain') || s.includes('web3') || s.includes('crypto') || s.includes('defi')) return 'blockchain_tech';
      if (s.includes('archives') || s.includes('records management') || s.includes('preservation')) return 'intl_archives';
      if (s.includes('global legal') || s.includes('global law')) return 'global_legal';
      if (s.includes('global insurance')) return 'global_insurance';
      if (s.includes('research') || s.includes('r&d') || s.includes('intellectual property') || s.includes('software')) return 'ip_research';
      if (s.includes('pharmaceutical') || s.includes('pharma') || s.includes('drug') || s.includes('biotech')) return 'pharma';
      if (s.includes('automotive manufacturing') || s.includes('auto manufacturing') || s.includes('motor vehicle') || s.includes('vehicle manufacturer')) return 'auto_oem';
      return 'institutional'; // default
    };

    // Determine role from title
    const mapRole = (title) => {
      const t = (title || '').toLowerCase();
      if (t.includes('chief digital') || t.includes('cdo')) return 'uae_redev';
      if (t.includes('chief technology') || t.includes('cto')) return 'uae_redev';
      if (t.includes('chief information') || t.includes('cio')) return 'it';
      if (t.includes('chief compliance') || t.includes('cco')) return 'compliance';
      if (t.includes('chief operating') || t.includes('coo')) return 'ops';
      if (t.includes('digital transform')) return 'uae_redev';
      if (t.includes('compliance') || t.includes('integrity')) return 'compliance';
      if (t.includes('supply chain')) return 'auto_supply';
      if (t.includes('quality') || t.includes('qc') || t.includes('qa')) return 'pharma_qa';
      if (t.includes('legal') || t.includes('counsel') || t.includes('attorney')) return 'legal';
      if (t.includes('finance') || t.includes('financial')) return 'finance';
      if (t.includes('operations') || t.includes('ops')) return 'ops';
      if (t.includes('record') || t.includes('clerk') || t.includes('register of deeds') || t.includes('fiscal officer')) return 'recorder';
      if (t.includes('it director') || t.includes('information technology') || t.includes('it security') || t.includes('it infrastructure') || t.includes('cyber')) return 'it';
      return 'compliance';
    };

    let imported = 0, skipped = 0, duplicates = 0;
    const errors = [];

    for (let i = 1; i < lines.length; i++) {
      try {
        // Handle quoted CSV values with commas inside
        const row = [];
        let current = '';
        let inQuotes = false;
        for (const char of lines[i]) {
          if (char === '"') { inQuotes = !inQuotes; }
          else if (char === ',' && !inQuotes) { row.push(current.trim()); current = ''; }
          else { current += char; }
        }
        row.push(current.trim());

        const email = getField(row, 'email', 'work_email', 'email_address');
        if (!email || !email.includes('@')) { skipped++; continue; }

        const firstName = getField(row, 'first_name', 'first name');
        const lastName = getField(row, 'last_name', 'last name');
        const fullName = getField(row, 'full_name') || `${firstName} ${lastName}`.trim();
        if (!fullName || fullName === '') { skipped++; continue; }

        const company = getField(row, 'company', 'organization', 'company_name', 'account_name');
        const title = getField(row, 'title', 'job_title', 'job title');
        const apolloIndustry = getField(row, 'industry', 'company_industry');
        const country = getField(row, 'country');
        const linkedin = getField(row, 'linkedin_url', 'person_linkedin_url');

        // Determine industry — UAE companies get uae_ prefix
        let industry = mapIndustry(apolloIndustry);
        const isUAE = country && (country.toLowerCase().includes('united arab') || country.toLowerCase().includes('uae'));
        if (isUAE && industry === 'title_escrow') industry = 'uae_realestate';
        if (isUAE && industry === 'auto') industry = 'uae_auto';

        const role = mapRole(title);

        // Check duplicate
        const exists = await pool.query('SELECT id FROM outreach_contacts WHERE email=$1', [email.toLowerCase()]);
        if (exists.rows.length > 0) { duplicates++; continue; }

        // Calculate priority score
        const pscore = (() => {
          let score = 0;
          const t = title.toLowerCase();
          const ind = industry;
          if (['government','title_escrow','legal','auto','construction','pe_ma','pharma','aviation','uae_realestate','uae_auto'].includes(ind)) score += 3;
          if (['government','regulated','institutional','insurance','accounting','pharma','aviation','uae_realestate','uae_auto'].includes(ind)) score += 2;
          if (['risk','compliance','fraud','audit','legal','counsel','investigation','integrity','claims','lien'].some(k => t.includes(k))) score += 3;
          if (['director','vp ','vice president','chief','head of','partner','officer','president','counsel'].some(k => t.includes(k))) score += 1;
          return Math.min(score, 12);
        })();

        await pool.query(
          `INSERT INTO outreach_contacts (name, email, company, title, industry, tier, priority_score, pipeline_stage, pain_status, use_case, status, first_sent_at, last_contact_at)
           VALUES ($1,$2,$3,$4,$5,'primary',$6,'targeted','unaware',$7,'pending',NOW(),NOW())`,
          [fullName, email.toLowerCase(), company || '', title || '', industry, pscore, `Apollo Import — ${apolloIndustry || industry}`]
        );

        await pool.query(
          `INSERT INTO outreach_events (contact_id, event_type, event_source, metadata, occurred_at)
           SELECT id, 'imported', 'apollo_csv', $1, NOW() FROM outreach_contacts WHERE email=$2`,
          [JSON.stringify({ source: 'apollo', linkedin, country, original_industry: apolloIndustry }), email.toLowerCase()]
        );

        imported++;
      } catch (e) {
        errors.push(`Row ${i}: ${e.message}`);
        skipped++;
      }
    }

    res.json({
      success: true,
      imported,
      duplicates,
      skipped,
      total_rows: lines.length - 1,
      errors: errors.slice(0, 10),
      message: `Imported ${imported} new contacts. ${duplicates} duplicates skipped. ${skipped} rows invalid.`
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get(['/api/admin/import/pending', '/admin/import/pending'], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: 'Unauthorized.' });
  try {
    const result = await pool.query("SELECT COUNT(*) as count FROM outreach_contacts WHERE status='pending'");
    res.json({ pending: parseInt(result.rows[0].count) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post(['/api/admin/import/send-pending', '/admin/import/send-pending'], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: 'Unauthorized.' });
  try {
    const limit = Math.min(parseInt(req.body?.limit) || 50, 200);
    const contacts = await pool.query(
      "SELECT * FROM outreach_contacts WHERE status='pending' AND email IS NOT NULL ORDER BY priority_score DESC LIMIT $1",
      [limit]
    );
    res.json({ success: true, queued: contacts.rows.length, message: `Sending to ${contacts.rows.length} pending contacts in background.` });
    // Fire and forget
    (async () => {
      const { Resend } = await import('resend');
      const resend = new Resend(process.env.RESEND_API_KEY);
      let sent = 0, failed = 0;
      for (const contact of contacts.rows) {
        // Skip generic "Team [Company]" contacts — no real person, high bounce/spam risk
        if (/^team\b/i.test((contact.name || '').trim())) {
          await pool.query("UPDATE outreach_contacts SET status='suppressed', suppressed_reason='no_named_contact', suppressed_at=NOW() WHERE id=$1", [contact.id]);
          failed++;
          continue;
        }
        // Skip generic role email addresses that slipped through on import
        if (SKIP_EMAIL_PATTERNS.test(contact.email)) {
          await pool.query("UPDATE outreach_contacts SET status='suppressed', suppressed_reason='generic_email', suppressed_at=NOW() WHERE id=$1", [contact.id]);
          failed++;
          continue;
        }
        try {
          const replyTag = crypto.randomBytes(8).toString('hex');
          const isUAE = ['uae_realestate','uae_auto'].includes(contact.industry);
          // Fall back to the best role for the industry when role is generic
          const industryDefaultRole = {
            government: 'recorder', title_escrow: 'title_ops', legal: 'transact',
            auto: 'dealer', construction: 'lien', pe_ma: 'deal',
            healthcare: 'healthcare', supply_chain: 'trade_docs',
            education: 'education', ip_research: 'ip_timestamp', insurance: 'claims',
            blockchain_tech: 'blockchain_partner', auto_oem: 'auto_oem', pharma: 'pharma_cco',
            intl_archives: 'intl_archives', global_legal: 'global_law_firm', global_insurance: 'global_insurance',
            real_estate: 'real_estate_ops', university_research: 'university_research',
            gov_regulator: 'gov_regulator', construction_detail: 'construction_eng',
          }[contact.industry] || 'compliance';
          const emailBody = isUAE
            ? UAE_EMAIL(contact.name, contact.company, contact.role || 'uae_redev')
            : INITIAL_EMAIL(contact.name, contact.company, contact.industry, contact.role || industryDefaultRole);
          const subject = isUAE
            ? `Aligning ${contact.company} with Dubai's 2026 Paperless Mandate`
            : `Quick question for ${contact.company}`;
          const fromAddr = (contact.industry === 'government' || contact.industry === 'gov_regulator')
            ? 'Scott Kiersten <gov@proofdeed.com>'
            : 'Scott Kiersten <info@proofdeed.com>';

          await resend.emails.send({
            from: fromAddr,
            reply_to: fromAddr,
            to: contact.email,
            subject,
            text: emailBody,
          });

          await pool.query(
            "UPDATE outreach_contacts SET status='sent', reply_to_tag=$1, pipeline_stage='contacted', first_sent_at=NOW(), last_contact_at=NOW() WHERE id=$2",
            [replyTag, contact.id]
          );
          await pool.query(
            `INSERT INTO outreach_events (contact_id, event_type, event_source, metadata, occurred_at) VALUES ($1,'sent','import_send',$2,NOW())`,
            [contact.id, JSON.stringify({ subject })]
          );
          sent++;
          await new Promise(r => setTimeout(r, 1500)); // 1.5s between sends for deliverability
        } catch (e) {
          console.error(`[ImportSend] Failed ${contact.email}:`, e.message);
          failed++;
        }
      }
      console.log(`[ImportSend] Done. Sent: ${sent}, Failed: ${failed}`);
    })();
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ---------------- ADMIN: AFFILIATES ---------------- */

// GET /api/admin/affiliates/stats — summary stats
app.get(['/api/admin/affiliates/stats', '/admin/affiliates/stats'], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: 'Unauthorized.' });
  try {
    const totalAffiliates = (await pool.query('SELECT COUNT(*) FROM affiliates')).rows[0].count;
    const totalReferrals = (await pool.query('SELECT COUNT(*) FROM affiliate_referrals')).rows[0].count;
    const totalConversions = (await pool.query("SELECT COUNT(*) FROM affiliate_referrals WHERE status='converted'")).rows[0].count;
    const pendingCommission = (await pool.query("SELECT COALESCE(SUM(commission_amount),0) as total FROM affiliate_referrals WHERE commission_status='pending' AND status='converted'")).rows[0].total;
    const totalPaid = (await pool.query("SELECT COALESCE(SUM(commission_amount),0) as total FROM affiliate_referrals WHERE commission_status='paid'")).rows[0].total;
    res.json({ totalAffiliates: parseInt(totalAffiliates), totalReferrals: parseInt(totalReferrals), totalConversions: parseInt(totalConversions), pendingCommission: parseFloat(pendingCommission), totalPaid: parseFloat(totalPaid) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/admin/affiliates — list all with computed stats
app.get(['/api/admin/affiliates', '/admin/affiliates'], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: 'Unauthorized.' });
  try {
    const result = await pool.query(`
      SELECT a.*,
        COUNT(DISTINCT r.id) as total_referrals,
        COUNT(DISTINCT CASE WHEN r.status='converted' THEN r.id END) as total_conversions,
        COALESCE(SUM(CASE WHEN r.commission_status='pending' AND r.status='converted' THEN r.commission_amount END),0) as pending_commission,
        COALESCE(SUM(CASE WHEN r.commission_status='paid' THEN r.commission_amount END),0) as total_paid
      FROM affiliates a
      LEFT JOIN affiliate_referrals r ON r.affiliate_id = a.id
      GROUP BY a.id
      ORDER BY a.created_at DESC
    `);
    res.json({ affiliates: result.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/admin/affiliates — create new affiliate
app.post(['/api/admin/affiliates', '/admin/affiliates'], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: 'Unauthorized.' });
  try {
    const { name, email, company, commission_rate, commission_type, flat_amount, payout_method, payout_email, notes, contact_id } = req.body;
    if (!name || !email) return res.status(400).json({ error: 'name and email required.' });
    const referral_code = crypto.randomBytes(4).toString('hex');
    const result = await pool.query(
      `INSERT INTO affiliates (name, email, company, referral_code, commission_rate, commission_type, flat_amount, payout_method, payout_email, notes, contact_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,
      [name, email, company || null, referral_code, commission_rate || 20.00, commission_type || 'percentage', flat_amount || null, payout_method || 'manual', payout_email || null, notes || null, contact_id || null]
    );
    res.json({ affiliate: result.rows[0] });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Affiliate with this email already exists.' });
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/admin/affiliates/:id — update affiliate
app.put(['/api/admin/affiliates/:id', '/admin/affiliates/:id'], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: 'Unauthorized.' });
  try {
    const { status, commission_rate, payout_method, payout_email, notes, company } = req.body;
    const result = await pool.query(
      `UPDATE affiliates SET
        status = COALESCE($1, status),
        commission_rate = COALESCE($2, commission_rate),
        payout_method = COALESCE($3, payout_method),
        payout_email = COALESCE($4, payout_email),
        notes = COALESCE($5, notes),
        company = COALESCE($6, company)
       WHERE id=$7 RETURNING *`,
      [status || null, commission_rate || null, payout_method || null, payout_email || null, notes || null, company || null, req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Affiliate not found.' });
    res.json({ affiliate: result.rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/admin/affiliates/:id/referrals — list referrals for one affiliate
app.get(['/api/admin/affiliates/:id/referrals', '/admin/affiliates/:id/referrals'], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: 'Unauthorized.' });
  try {
    const result = await pool.query(
      'SELECT * FROM affiliate_referrals WHERE affiliate_id=$1 ORDER BY created_at DESC',
      [req.params.id]
    );
    res.json({ referrals: result.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/admin/affiliates/:id/payout — record a manual payout
app.post(['/api/admin/affiliates/:id/payout', '/admin/affiliates/:id/payout'], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: 'Unauthorized.' });
  try {
    const { amount, payout_method, reference, notes } = req.body;
    if (!amount || isNaN(parseFloat(amount))) return res.status(400).json({ error: 'Valid amount required.' });
    const affId = req.params.id;
    const payout = await pool.query(
      `INSERT INTO affiliate_payouts (affiliate_id, amount, payout_method, reference, notes, status, paid_at)
       VALUES ($1,$2,$3,$4,$5,'paid',NOW()) RETURNING *`,
      [affId, parseFloat(amount), payout_method || 'manual', reference || null, notes || null]
    );
    await pool.query(
      "UPDATE affiliate_referrals SET commission_status='paid' WHERE affiliate_id=$1 AND commission_status='pending' AND status='converted'",
      [affId]
    );
    res.json({ payout: payout.rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET /api/admin/affiliates/payout-settings — get current payout day (1-28)
app.get(['/api/admin/affiliates/payout-settings', '/admin/affiliates/payout-settings'], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: 'Unauthorized.' });
  try {
    const row = await pool.query("SELECT value FROM lead_engine_state WHERE key='affiliate_payout_day'").catch(() => ({ rows: [] }));
    const day = row.rows[0] ? parseInt(row.rows[0].value) : 1;
    // Calculate next payout date
    const now = new Date();
    let next = new Date(now.getFullYear(), now.getMonth(), day);
    if (next <= now) next = new Date(now.getFullYear(), now.getMonth() + 1, day);
    // Get total pending across all affiliates
    const pending = await pool.query(
      "SELECT COALESCE(SUM(commission_amount),0) as total FROM affiliate_referrals WHERE commission_status='pending' AND status='converted'"
    ).catch(() => ({ rows: [{ total: 0 }] }));
    const affCount = await pool.query(
      "SELECT COUNT(DISTINCT affiliate_id) as count FROM affiliate_referrals WHERE commission_status='pending' AND status='converted'"
    ).catch(() => ({ rows: [{ count: 0 }] }));
    const isDueToday = now.getDate() === day;
    res.json({
      payout_day: day,
      next_payout_date: next.toISOString().split('T')[0],
      is_due_today: isDueToday,
      pending_total: parseFloat(pending.rows[0].total),
      affiliates_owed: parseInt(affCount.rows[0].count),
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// PUT /api/admin/affiliates/payout-settings — set payout day
app.put(['/api/admin/affiliates/payout-settings', '/admin/affiliates/payout-settings'], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: 'Unauthorized.' });
  try {
    const { payout_day } = req.body;
    const day = parseInt(payout_day);
    if (!day || day < 1 || day > 28) return res.status(400).json({ error: 'Payout day must be 1–28.' });
    await pool.query(
      `INSERT INTO lead_engine_state (key, value, updated_at) VALUES ('affiliate_payout_day',$1,NOW())
       ON CONFLICT (key) DO UPDATE SET value=$1, updated_at=NOW()`,
      [String(day)]
    );
    res.json({ payout_day: day });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── PUT /api/admin/affiliates/:id/brand — set white-label brand config
app.put(['/api/admin/affiliates/:id/brand', '/admin/affiliates/:id/brand'], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: 'Unauthorized.' });
  try {
    const { white_label_enabled, brand_name, brand_logo_url, brand_color, brand_tagline, brand_website } = req.body;
    const result = await pool.query(
      `UPDATE affiliates SET
        white_label_enabled = COALESCE($1, white_label_enabled),
        brand_name          = COALESCE($2, brand_name),
        brand_logo_url      = COALESCE($3, brand_logo_url),
        brand_color         = COALESCE($4, brand_color),
        brand_tagline       = COALESCE($5, brand_tagline),
        brand_website       = COALESCE($6, brand_website)
       WHERE id=$7 RETURNING *`,
      [
        white_label_enabled !== undefined ? white_label_enabled : null,
        brand_name || null,
        brand_logo_url || null,
        brand_color || null,
        brand_tagline || null,
        brand_website || null,
        req.params.id
      ]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Affiliate not found.' });
    res.json({ affiliate: result.rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── GET /api/partner/:code — public white-label partner portal (HTML)
app.get(['/api/partner/:code', '/partner/:code'], async (req, res) => {
  try {
    const { code } = req.params;
    const result = await pool.query(
      `SELECT * FROM affiliates WHERE referral_code=$1 AND status='active'`,
      [code]
    );
    if (!result.rows.length) return res.status(404).send('<h1>Partner portal not found.</h1>');
    const aff = result.rows[0];

    const brandName    = aff.brand_name    || aff.company || 'Document Certification';
    const brandColor   = aff.brand_color   || '#1a3a8e';
    const brandTagline = aff.brand_tagline || 'Tamper-proof blockchain document certification for your organization.';
    const brandLogo    = aff.brand_logo_url;
    const brandWebsite = aff.brand_website || '#';
    const refCode      = aff.referral_code;

    // Track the portal visit as a referral click
    await pool.query(
      `INSERT INTO affiliate_referrals (affiliate_id, referral_code, status, created_at)
       VALUES ($1,$2,'clicked',NOW())`,
      [aff.id, refCode]
    ).catch(() => {});

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>${brandName} — Document Certification</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:Georgia,serif;background:#f0f0ee;min-height:100vh;display:flex;flex-direction:column}
    .topbar{height:5px;background:linear-gradient(90deg,${brandColor},${brandColor}cc,${brandColor})}
    header{background:#fff;border-bottom:1px solid #e5e5e5;padding:24px 40px;display:flex;align-items:center;justify-content:space-between}
    .logo-wrap{display:flex;align-items:center;gap:16px}
    .logo-img{height:48px;width:auto;object-fit:contain}
    .logo-text{font-size:22px;font-weight:700;color:#111;letter-spacing:-0.5px}
    .header-cta{background:${brandColor};color:#fff;padding:10px 22px;border-radius:6px;text-decoration:none;font-family:sans-serif;font-size:14px;font-weight:600}
    .hero{max-width:760px;margin:60px auto;padding:0 24px;text-align:center}
    .hero h1{font-size:36px;color:#111;font-weight:700;line-height:1.2;margin-bottom:16px}
    .hero p{font-size:17px;color:#555;line-height:1.7;margin-bottom:40px}
    .cta-btn{display:inline-block;background:${brandColor};color:#fff;padding:16px 36px;border-radius:8px;text-decoration:none;font-family:sans-serif;font-size:16px;font-weight:700;margin-bottom:12px}
    .cta-sub{font-size:13px;color:#999;font-family:sans-serif}
    .features{max-width:900px;margin:0 auto 60px;padding:0 24px;display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:24px}
    .feature{background:#fff;border:1px solid #e5e5e5;border-radius:8px;padding:28px;border-top:3px solid ${brandColor}}
    .feature h3{font-size:16px;font-weight:700;color:#111;margin-bottom:10px;font-family:sans-serif}
    .feature p{font-size:14px;color:#666;line-height:1.6;font-family:sans-serif}
    .how{background:#fff;border-top:1px solid #e5e5e5;border-bottom:1px solid #e5e5e5;padding:60px 24px;text-align:center}
    .how h2{font-size:26px;font-weight:700;color:#111;margin-bottom:40px}
    .steps{max-width:800px;margin:0 auto;display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:24px}
    .step{text-align:center}
    .step-num{width:44px;height:44px;border-radius:50%;background:${brandColor};color:#fff;display:flex;align-items:center;justify-content:center;font-size:18px;font-weight:700;font-family:sans-serif;margin:0 auto 12px}
    .step h4{font-size:15px;font-weight:700;color:#111;font-family:sans-serif;margin-bottom:6px}
    .step p{font-size:13px;color:#666;font-family:sans-serif;line-height:1.5}
    .bottom-cta{text-align:center;padding:60px 24px}
    .bottom-cta h2{font-size:26px;font-weight:700;color:#111;margin-bottom:16px}
    .bottom-cta p{font-size:16px;color:#555;margin-bottom:32px;font-family:sans-serif}
    footer{margin-top:auto;padding:24px;text-align:center;font-family:sans-serif;font-size:12px;color:#aaa;border-top:1px solid #e5e5e5;background:#fff}
    footer a{color:#aaa;text-decoration:none}
  </style>
</head>
<body>
  <div class="topbar"></div>
  <header>
    <div class="logo-wrap">
      ${brandLogo ? `<img src="${brandLogo}" alt="${brandName} logo" class="logo-img"/>` : `<span class="logo-text">${brandName}</span>`}
    </div>
    <a href="https://proofdeed.com/document?ref=${refCode}" class="header-cta">Get Started</a>
  </header>

  <div class="hero">
    <h1>${brandName}<br/>Document Certification</h1>
    <p>${brandTagline}</p>
    <a href="https://proofdeed.com/document?ref=${refCode}" class="cta-btn">Certify a Document</a>
    <div class="cta-sub">No account required &nbsp;·&nbsp; Instant certificate &nbsp;·&nbsp; Court-admissible</div>
  </div>

  <div class="features">
    <div class="feature">
      <h3>Tamper-Proof</h3>
      <p>Every document is anchored to the Polygon blockchain the moment it's certified. Any alteration is immediately detectable — permanently.</p>
    </div>
    <div class="feature">
      <h3>Court-Admissible</h3>
      <p>Certificates satisfy Federal Rules of Evidence Rule 901. Independently verifiable by any court, auditor, or regulator without access to internal systems.</p>
    </div>
    <div class="feature">
      <h3>Instant & Easy</h3>
      <p>Upload a document, receive a blockchain certificate in seconds. No software to install, no account required for one-time certifications.</p>
    </div>
  </div>

  <div class="how">
    <h2>How It Works</h2>
    <div class="steps">
      <div class="step">
        <div class="step-num">1</div>
        <h4>Upload</h4>
        <p>Upload any document — PDF, image, contract, deed, or record.</p>
      </div>
      <div class="step">
        <div class="step-num">2</div>
        <h4>Certify</h4>
        <p>A unique fingerprint is created and anchored to the Polygon blockchain instantly.</p>
      </div>
      <div class="step">
        <div class="step-num">3</div>
        <h4>Prove</h4>
        <p>Share your certificate. Anyone can verify it — no account needed.</p>
      </div>
    </div>
  </div>

  <div class="bottom-cta">
    <h2>Ready to protect your documents?</h2>
    <p>Join organizations using blockchain certification to eliminate document fraud and disputes.</p>
    <a href="https://proofdeed.com/document?ref=${refCode}" class="cta-btn">Certify Your First Document</a>
  </div>

  <footer>
    <p>Trust Records provided by <a href="https://proofdeed.com" target="_blank">ProofDeed</a> &mdash; Trust Infrastructure Platform &nbsp;|&nbsp; <a href="https://proofdeed.com/verify">Verify a Trust Record</a></p>
  </footer>
</body>
</html>`;

    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  } catch (err) {
    console.error('[PartnerPortal]', err.message);
    res.status(500).send('<h1>Something went wrong. Please try again.</h1>');
  }
});

// ── GET /api/partner/:code/config — returns brand config JSON (for frontend embedding)
app.get('/api/partner/:code/config', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT referral_code, brand_name, brand_logo_url, brand_color, brand_tagline, brand_website, company, white_label_enabled
       FROM affiliates WHERE referral_code=$1 AND status='active'`,
      [req.params.code]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Partner not found.' });
    res.json({ partner: result.rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Affiliate monthly payout reminder — runs daily at 8am PT, fires on payout day
cron.schedule('0 8 * * *', async () => {
  try {
    const row = await pool.query("SELECT value FROM lead_engine_state WHERE key='affiliate_payout_day'").catch(() => ({ rows: [] }));
    const payoutDay = row.rows[0] ? parseInt(row.rows[0].value) : 1;
    const today = new Date();
    if (today.getDate() !== payoutDay) return; // not payout day, skip

    console.log('[AffiliatePayouts] Payout day — generating statements...');
    const { Resend } = await import('resend');
    const resend = new Resend(process.env.RESEND_API_KEY);

    // Get all affiliates with pending commissions
    const affiliates = await pool.query(`
      SELECT a.id, a.name, a.email, a.company, a.referral_code, a.payout_method, a.payout_email, a.commission_rate,
        COUNT(DISTINCT r.id) FILTER (WHERE r.status='converted') as conversions,
        COUNT(DISTINCT r.id) FILTER (WHERE r.commission_status='pending' AND r.status='converted') as pending_count,
        COALESCE(SUM(r.commission_amount) FILTER (WHERE r.commission_status='pending' AND r.status='converted'),0) as pending_amount,
        COALESCE(SUM(r.commission_amount) FILTER (WHERE r.commission_status='paid'),0) as total_paid
      FROM affiliates a
      LEFT JOIN affiliate_referrals r ON r.affiliate_id = a.id
      WHERE a.status = 'active'
      GROUP BY a.id
      HAVING COALESCE(SUM(r.commission_amount) FILTER (WHERE r.commission_status='pending' AND r.status='converted'),0) > 0
    `);

    if (!affiliates.rows.length) {
      console.log('[AffiliatePayouts] No pending payouts this month.');
      return;
    }

    const totalOwed = affiliates.rows.reduce((s, a) => s + parseFloat(a.pending_amount), 0);
    const month = today.toLocaleString('default', { month: 'long', year: 'numeric' });

    // Send admin summary
    const adminLines = affiliates.rows.map(a =>
      `  • ${a.name} (${a.company || 'N/A'}) — $${parseFloat(a.pending_amount).toFixed(2)} via ${a.payout_method}${a.payout_email ? ' @ ' + a.payout_email : ''} — ${a.pending_count} conversion(s)`
    ).join('\n');

    await sendAlertEmail(
      `💸 ProofDeed Affiliate Payout Due — ${month} — $${totalOwed.toFixed(2)} Total`,
      `Affiliate Payout Summary — ${month}\n\nTotal owed: $${totalOwed.toFixed(2)} across ${affiliates.rows.length} affiliate(s)\n\n${adminLines}\n\nMark payouts as complete in the admin:\nhttps://proofdeed.com/admin\n\n(Tab: 🤝 Affiliates)`
    ).catch(() => {});

    // Send each affiliate their statement
    for (const aff of affiliates.rows) {
      const referrals = await pool.query(
        `SELECT referred_name, referred_company, plan, commission_amount, converted_at
         FROM affiliate_referrals
         WHERE affiliate_id=$1 AND commission_status='pending' AND status='converted'
         ORDER BY converted_at DESC`,
        [aff.id]
      );
      const refLines = referrals.rows.map(r =>
        `  • ${r.referred_name || 'New Customer'} (${r.referred_company || 'N/A'}) — ${r.plan || 'Paid Plan'} — Commission: $${parseFloat(r.commission_amount).toFixed(2)}`
      ).join('\n');

      await resend.emails.send({
        from: 'Scott Kiersten <gov@proofdeed.com>',
        to: aff.email,
        subject: `Your ProofDeed Commission Statement — ${month}`,
        text: `Hi ${aff.name.split(' ')[0]},

Here is your ProofDeed affiliate commission statement for ${month}.

Pending Commission: $${parseFloat(aff.pending_amount).toFixed(2)}
Referrals this period: ${aff.pending_count}

Breakdown:
${refLines || '  (No individual referral details available)'}

Your referral link: https://proofdeed.com/ref/${aff.referral_code}
Commission rate: ${aff.commission_rate}%

Payment will be sent to you via ${aff.payout_method}${aff.payout_email ? ' (' + aff.payout_email + ')' : ''} shortly.

If you have any questions, reply to this email.

Thank you for being a ProofDeed partner.

Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`,
      }).catch(e => console.error(`[AffiliatePayouts] Failed to email ${aff.email}:`, e.message));

      console.log(`[AffiliatePayouts] Statement sent to ${aff.name} (${aff.email}) — $${aff.pending_amount}`);
    }

    console.log(`[AffiliatePayouts] Done. Total owed: $${totalOwed.toFixed(2)} to ${affiliates.rows.length} affiliates.`);
  } catch (err) {
    console.error('[AffiliatePayouts] Error:', err.message);
  }
}, { timezone: 'America/Los_Angeles' });

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

  // ── California SB 255 Mandate Targets (58 counties must implement deed notification)
  { industry: 'government', role: 'recorder', tier: 'primary', title: 'CA County Recorder SB255',   query: '"County Recorder" OR "County Clerk-Recorder" California "deed fraud" OR "property fraud" OR "SB 255" contact email site:*.ca.gov OR site:*.gov' },
  { industry: 'government', role: 'recorder', tier: 'primary', title: 'Clark County Recorder',       query: '"Clark County Recorder" OR "Clark County" recorder "property fraud alert" contact email site:*.gov' },
  { industry: 'government', role: 'recorder', tier: 'primary', title: 'El Dorado County Recorder',   query: '"El Dorado County" recorder OR "property monitoring" deed fraud contact email site:eldoradocounty.ca.gov OR site:*.gov' },
  { industry: 'government', role: 'legal',    tier: 'primary', title: 'Ventura County REFAT',        query: '"Ventura County" "Real Estate Fraud" REFAT OR "district attorney" deed fraud contact email site:ventura.org OR site:*.gov' },
  { industry: 'government', role: 'recorder', tier: 'primary', title: 'CA Recorder Deed Fraud',      query: 'California "County Recorder" "deed fraud" OR "title fraud" notification program contact email 2025 2026 site:*.ca.gov' },
  { industry: 'government', role: 'recorder', tier: 'primary', title: 'CA Large County Recorders',   query: '"Los Angeles County Registrar" OR "San Diego County Recorder" OR "Orange County Clerk" recorder contact email site:*.gov' },

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
  { industry: 'auto', role: 'digital',    tier: 'expansion',  title: 'VP of Operations — Carvana/CarMax', query: 'VP Operations OR "Head of Title" OR "Title Operations" Carvana OR CarMax OR Vroom site:linkedin.com email contact' },
  { industry: 'auto', role: 'digital',    tier: 'expansion',  title: 'Head of Title Operations — Online Auto', query: '"Head of Title" OR "Title Operations Manager" Carvana OR CarMax OR AutoNation USA email contact' },
  { industry: 'auto', role: 'digital',    tier: 'expansion',  title: 'Compliance Director — Auto Platform', query: '"Compliance Director" OR "Head of Compliance" Carvana OR CarMax OR Cox Automotive USA email contact' },

  // ── TIER 5: Extended Buyers
  { industry: 'auto', role: 'insurance',  tier: 'expansion',  title: 'Total Loss Director — Auto Insurer', query: '"Total Loss Director" OR "Total Loss Manager" "State Farm" OR "GEICO" OR "Progressive" OR "Allstate" USA email contact' },
  { industry: 'auto', role: 'insurance',  tier: 'expansion',  title: 'Auto Claims VP — Major Insurer',     query: '"VP of Claims" OR "Claims Director" auto insurance "State Farm" OR "GEICO" OR "Progressive" USA email contact' },

  // ── TIER 6: VIN-Integrity / OEM Supply Chain
  { industry: 'auto', role: 'auto_supply', tier: 'primary',   title: 'VP Supply Chain — Ford/GM/Stellantis', query: '"VP of Supply Chain" OR "VP Supply Chain" Ford OR "General Motors" OR Stellantis OR Toyota OR Honda USA email contact' },
  { industry: 'auto', role: 'auto_cdo',   tier: 'primary',    title: 'Chief Digital Officer — Major OEM',    query: '"Chief Digital Officer" OR "CDO" Ford OR "General Motors" OR Toyota OR BMW OR Mercedes OR Honda USA email contact' },
  { industry: 'auto', role: 'auto_remarketing', tier: 'primary', title: 'Head of Remarketing — OEM/Fleet',  query: '"Head of Remarketing" OR "Director of Remarketing" Ford OR GM OR Toyota OR "Cox Automotive" OR Manheim USA email contact' },
  { industry: 'auto', role: 'auto_iso',   tier: 'primary',    title: 'Quality Director — IATF Automotive',  query: '"Director of Quality" OR "VP Quality" Ford OR "General Motors" OR Toyota OR Honda IATF OR ISO 16949 USA email contact' },
  // Sandbox Design Partner targets — deeper automotive title & supply chain roles
  { industry: 'auto', role: 'auto_remarketing2', tier: 'primary', title: 'Head of Remarketing Ops — Fleet', query: '"Head of Remarketing" OR "VP Fleet Remarketing" Hertz OR Enterprise OR "Cox Automotive" OR Manheim OR ADESA USA email contact' },
  { industry: 'auto', role: 'auto_warranty',  tier: 'primary',  title: 'Warranty Director — Auto OEM',       query: '"Director of Warranty" OR "Warranty Quality Director" Ford OR "General Motors" OR Toyota OR Stellantis USA email contact' },
  { industry: 'auto', role: 'auto_dds',       tier: 'primary',  title: 'VP Digital Solutions — CDK/Reynolds', query: '"VP" OR "Director" digital solutions OR dealer technology CDK OR "Reynolds and Reynolds" OR DealerSocket OR Tekion USA email contact' },
  { industry: 'auto', role: 'auto_coo',       tier: 'primary',  title: 'Supply Chain Transparency — OEM',    query: '"Supply Chain" transparency OR integrity OR compliance director Ford OR Toyota OR Honda OR GM OR Stellantis USA email contact' },
  { industry: 'auto', role: 'auto_blockchain',tier: 'primary',  title: 'Blockchain/Digital Identity — Auto', query: '"Blockchain" OR "Digital Identity" OR "Vehicle Identity" architect OR director Ford OR GM OR BMW OR Toyota USA site:linkedin.com email' },

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
  { industry: 'institutional', role: 'inst_ciso',  tier: 'primary',    title: 'CISO (Higher Ed / Healthcare)', query: '"Chief Information Security Officer" OR "CISO" university OR hospital OR "health system" USA contact email' },
  { industry: 'institutional', role: 'inst_registrar', tier: 'primary', title: 'University Registrar (Credential Integrity)', query: '"University Registrar" OR "Registrar" diploma OR transcript OR credential integrity USA contact email' },
  { industry: 'institutional', role: 'inst_him',   tier: 'primary',    title: 'CISO / HIM Director (Medical Records)', query: '"Health Information" director OR "Medical Records" CISO hospital "health system" USA contact email' },

  // ── TIER 6: Financial Institutions
  { industry: 'institutional', role: 'financial',  tier: 'expansion',  title: 'Loan Documentation Manager',   query: '"Loan Documentation Manager" OR "Loan Docs Manager" bank USA contact email' },

  // ── TIER 7: PE / Finance / Insurance Trust-as-a-Service (new)
  { industry: 'institutional', role: 'inst_coo',   tier: 'primary',    title: 'COO (PE / Asset Manager)',      query: '"Chief Operating Officer" "private equity" OR "asset management" OR "hedge fund" USA contact email' },
  { industry: 'institutional', role: 'inst_ir',    tier: 'primary',    title: 'Head of Investor Relations (PE)', query: '"Head of Investor Relations" OR "Director of Investor Relations" "private equity" OR "fund" USA contact email' },
  { industry: 'institutional', role: 'inst_gcc',   tier: 'primary',    title: 'General Counsel / CCO (Fund)',  query: '"General Counsel" OR "Chief Compliance Officer" "private equity" OR "hedge fund" OR "investment fund" USA SEC contact email' },
  { industry: 'institutional', role: 'inst_dd',    tier: 'primary',    title: 'Director of Due Diligence',     query: '"Director of Due Diligence" OR "Head of Due Diligence" "private equity" OR "investment firm" USA contact email' },

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
  // Sandbox Design Partner targets — deeper institutional / finance roles
  { industry: 'institutional', role: 'inst_ethics', tier: 'primary', title: 'Chief Data Ethics Officer',               query: '"Chief Data Ethics Officer" OR "Head of Data Ethics" "financial modeling" OR "data integrity" USA contact email' },
  { industry: 'institutional', role: 'inst_fund',   tier: 'primary', title: 'Head of Fund Administration',             query: '"Head of Fund Administration" OR "Director Fund Administration" "private equity" OR "hedge fund" LP reporting USA contact email' },
  { industry: 'pe_ma',         role: 'inst_ma',     tier: 'primary', title: 'Managing Director of M&A Due Diligence',  query: '"Managing Director" "Due Diligence" OR "data room" OR "M&A" "private equity" USA contact email' },
  { industry: 'institutional', role: 'inst_aml',    tier: 'primary', title: 'Chief Compliance & AML Officer',          query: '"AML Officer" OR "Anti-Money Laundering" "Chief Compliance" "source of funds" USA contact email' },
  { industry: 'institutional', role: 'inst_digital_assets', tier: 'primary', title: 'Head of Digital Assets Regulatory', query: '"Digital Assets" regulatory OR compliance "traditional assets" OR "cryptographic" head OR director USA contact email' },

  // ════════════════════════════════════════════════════════
  // LIFE SCIENCES & PHARMA — ALCOA+ data integrity compliance
  // ════════════════════════════════════════════════════════
  { industry: 'pharma', role: 'pharma_qa',      tier: 'primary',    title: 'Head of Quality Assurance (Pharma)', query: '"Head of Quality Assurance" OR "VP of Quality" pharmaceutical OR "life sciences" OR biotech USA contact email' },
  { industry: 'pharma', role: 'pharma_qa',      tier: 'primary',    title: 'Quality Control Director (Pharma)',  query: '"Quality Control Director" OR "QC Director" pharmaceutical OR "life sciences" USA contact email' },
  { industry: 'pharma', role: 'pharma_cco',     tier: 'primary',    title: 'Chief Compliance Officer (Pharma)',  query: '"Chief Compliance Officer" pharmaceutical OR biotech OR "life sciences" FDA USA contact email' },
  { industry: 'pharma', role: 'pharma_cco',     tier: 'primary',    title: 'Regulatory Affairs Director (FDA)', query: '"Regulatory Affairs Director" OR "VP Regulatory Affairs" pharmaceutical FDA USA contact email' },
  { industry: 'pharma', role: 'pharma_supply',  tier: 'primary',    title: 'VP of Supply Chain Integrity',      query: '"VP of Supply Chain" OR "Director of Supply Chain Integrity" pharmaceutical OR "track and trace" USA contact email' },
  { industry: 'pharma', role: 'pharma_supply',  tier: 'primary',    title: 'Serialization & Track-Trace Manager', query: '"Serialization Manager" OR "Track and Trace" pharmaceutical supply chain USA contact email' },
  { industry: 'pharma', role: 'pharma_clinical',tier: 'primary',    title: 'VP Clinical Data Integrity',        query: '"Clinical Data Integrity" OR "VP Clinical Operations" pharmaceutical clinical trial USA contact email' },
  { industry: 'pharma', role: 'pharma_clinical',tier: 'primary',    title: 'Director of Clinical Data Management', query: '"Clinical Data Management" director OR VP pharmaceutical USA contact email' },
  // Sandbox Design Partner targets — deeper GXP / lab / logistics roles
  { industry: 'pharma', role: 'pharma_gxp',    tier: 'primary',    title: 'VP of Quality Systems (GXP)',        query: '"VP of Quality Systems" OR "VP Quality" GXP OR "Good Practice" pharmaceutical OR "life sciences" USA contact email' },
  { industry: 'pharma', role: 'pharma_trial',  tier: 'primary',    title: 'Head of Clinical Trial Data Management', query: '"Clinical Trial Data Management" OR "Head of Clinical Data" "raw data" pharmaceutical USA contact email' },
  { industry: 'pharma', role: 'pharma_serial', tier: 'primary',    title: 'Director of Product Serialization',  query: '"Director of Product Serialization" OR "Product Serialization" "digital fingerprint" OR "drug package" pharmaceutical USA contact email' },
  { industry: 'pharma', role: 'pharma_lims',   tier: 'primary',    title: 'LIMS Administrator',                 query: '"LIMS Administrator" OR "Laboratory Information Management System" pharmaceutical OR "life sciences" USA contact email' },
  { industry: 'pharma', role: 'pharma_coldchain', tier: 'primary', title: 'CTO of Pharma Logistics (Cold Chain)', query: '"Chief Technology Officer" OR "CTO" "pharma logistics" OR "cold chain" OR "shipping integrity" pharmaceutical USA contact email' },

  // ════════════════════════════════════════════════════════
  // AVIATION & AEROSPACE (MRO) — airworthiness documentation
  // ════════════════════════════════════════════════════════
  { industry: 'aviation', role: 'aviation_dom',  tier: 'primary',   title: 'Director of Maintenance (DOM)',      query: '"Director of Maintenance" airline OR MRO OR aviation USA contact email' },
  { industry: 'aviation', role: 'aviation_dom',  tier: 'primary',   title: 'VP of Aviation Safety',              query: '"VP of Aviation Safety" OR "Director of Aviation Safety" airline USA contact email' },
  { industry: 'aviation', role: 'aviation_cto',  tier: 'primary',   title: 'CTO of MRO Organization',            query: '"Chief Technology Officer" MRO OR "Maintenance Repair Overhaul" aviation USA contact email' },
  { industry: 'aviation', role: 'aviation_cto',  tier: 'primary',   title: 'Head of Digital Transformation (MRO)', query: '"Digital Transformation" MRO OR aviation maintenance USA director OR head contact email' },
  { industry: 'aviation', role: 'aviation_parts',tier: 'primary',   title: 'Parts Quality Director (Anti-Counterfeit)', query: '"Parts Quality" OR "counterfeit parts" director aviation aerospace USA contact email' },
  { industry: 'aviation', role: 'aviation_parts',tier: 'primary',   title: 'Director of Engineering Records',    query: '"Engineering Records" director OR manager aviation OR aerospace OR MRO USA contact email' },
  // Sandbox Design Partner targets — deeper airworthiness / SMS / records roles
  { industry: 'aviation', role: 'aviation_airworthy', tier: 'primary', title: 'Director of Airworthiness',            query: '"Director of Airworthiness" OR "Airworthiness Manager" airline OR aviation USA contact email' },
  { industry: 'aviation', role: 'aviation_logistics', tier: 'primary', title: 'VP of Component Support & Logistics',  query: '"VP of Component Support" OR "Component Logistics" OR "rotatable parts" aviation MRO USA contact email' },
  { industry: 'aviation', role: 'aviation_cdo',       tier: 'primary', title: 'Chief Digital Officer (MRO)',           query: '"Chief Digital Officer" MRO OR "electronic technical logs" OR "eTechLog" aviation USA contact email' },
  { industry: 'aviation', role: 'aviation_sms',       tier: 'primary', title: 'Aviation Safety Management System Lead', query: '"Safety Management System" OR "SMS" lead OR director aviation "incident report" OR "safety data" USA contact email' },
  { industry: 'aviation', role: 'aviation_records',   tier: 'primary', title: 'Head of Fleet Technical Records',      query: '"Fleet Technical Records" OR "Technical Records Manager" OR "Form 8130" aviation USA contact email' },

  // ════════════════════════════════════════════════════════
  // ANTI-FRAUD / TITLE INTEGRITY — highest pain, direct buyers
  // ════════════════════════════════════════════════════════
  // County Recorder — clouded titles, deed fraud
  { industry: 'government', role: 'anti_fraud', tier: 'primary',  title: 'County Recorder Anti-Fraud',     query: '"County Recorder" OR "Register of Deeds" "deed fraud" OR "title fraud" contact email county USA site:*.gov' },
  { industry: 'government', role: 'anti_fraud', tier: 'primary',  title: 'Chief Deputy County Recorder',   query: '"Chief Deputy Recorder" OR "Deputy Register of Deeds" county USA contact email site:*.gov' },

  // Secretary of State — RON / e-notarization
  { industry: 'government', role: 'ron',      tier: 'primary',    title: 'Secretary of State RON Director', query: '"Secretary of State" "remote online notarization" OR "RON" director OR counsel USA contact email site:*.gov' },
  { industry: 'government', role: 'ron',      tier: 'primary',    title: 'State Notary Division Director',  query: '"Notary Division" OR "Notary Program" director state government USA contact email site:*.gov' },

  // ALTA / Title Associations — insurance risk reduction
  { industry: 'title_escrow', role: 'alta',   tier: 'primary',    title: 'ALTA State Chapter Director',    query: '"American Land Title Association" OR "ALTA" state chapter director OR executive USA contact email' },
  { industry: 'title_escrow', role: 'alta',   tier: 'primary',    title: 'Title Insurance Underwriter',    query: '"title insurance" underwriter OR "underwriting counsel" USA contact email' },
  { industry: 'title_escrow', role: 'alta',   tier: 'primary',    title: 'Title Claims Manager',           query: '"title insurance" "claims manager" OR "claims director" USA contact email' },

  // USDA 2026 National Lenders of the Year — top USDA Rural Housing guaranteed loan partners
  { industry: 'title_escrow', role: 'mortgage_lender', tier: 'primary', title: 'HR Mortgage Corp — Compliance/Ops', query: '"HR Mortgage Corp" compliance OR operations OR "loan officer" director manager contact email' },
  { industry: 'title_escrow', role: 'mortgage_lender', tier: 'primary', title: 'Gum Tree Mortgage — Leadership', query: '"Gum Tree Mortgage" contact email director manager OR loan officer' },
  { industry: 'title_escrow', role: 'mortgage_lender', tier: 'primary', title: 'NVR Mortgage — Compliance/Ops', query: '"NVR Mortgage" compliance OR operations director manager contact email' },
  { industry: 'title_escrow', role: 'mortgage_lender', tier: 'primary', title: 'Lower LLC — Compliance/Ops', query: '"Lower LLC" OR "Lower.com" mortgage compliance operations director contact email' },
  { industry: 'title_escrow', role: 'mortgage_lender', tier: 'primary', title: 'Planet Home Lending — Compliance/Ops', query: '"Planet Home Lending" compliance OR operations director manager contact email' },
  { industry: 'title_escrow', role: 'mortgage_lender', tier: 'primary', title: 'United Wholesale Mortgage — Compliance/Tech', query: '"United Wholesale Mortgage" OR "UWM" compliance technology operations director contact email' },
  { industry: 'title_escrow', role: 'mortgage_lender', tier: 'primary', title: 'Click N Close — Leadership', query: '"Click N Close" OR "ClickNClose" mortgage director manager contact email' },
  { industry: 'title_escrow', role: 'mortgage_lender', tier: 'primary', title: 'NewRez LLC — Compliance/Ops', query: '"NewRez" OR "New Rez" mortgage compliance operations director contact email' },
  { industry: 'title_escrow', role: 'mortgage_lender', tier: 'primary', title: 'First Community Mortgage — Leadership', query: '"First Community Mortgage" director manager compliance contact email' },
  { industry: 'title_escrow', role: 'mortgage_lender', tier: 'primary', title: 'Kind Lending — Leadership', query: '"Kind Lending" mortgage director manager compliance contact email' },
  { industry: 'title_escrow', role: 'mortgage_lender', tier: 'primary', title: '1st Signature Lending — Leadership', query: '"1st Signature Lending" mortgage director manager compliance contact email' },
  { industry: 'title_escrow', role: 'mortgage_lender', tier: 'primary', title: 'Idaho Housing & Finance Association — Leadership', query: '"Idaho Housing" "Finance Association" director manager compliance contact email' },
  { industry: 'title_escrow', role: 'mortgage_lender', tier: 'primary', title: 'Virginia Housing Development Authority — Leadership', query: '"Virginia Housing Development Authority" OR "Virginia Housing" director manager compliance contact email' },
  { industry: 'title_escrow', role: 'mortgage_lender', tier: 'primary', title: 'PennyMac — Compliance/Ops', query: '"PennyMac" OR "Penny Mac" mortgage compliance operations director contact email' },
  { industry: 'title_escrow', role: 'mortgage_lender', tier: 'primary', title: 'Banco Popular de Puerto Rico — Mortgage Leadership', query: '"Banco Popular de Puerto Rico" mortgage director manager compliance contact email' },
  { industry: 'title_escrow', role: 'mortgage_lender', tier: 'primary', title: 'Guild Mortgage — Compliance/Tech', query: '"Guild Mortgage" compliance technology operations director contact email' },
  { industry: 'title_escrow', role: 'mortgage_lender', tier: 'primary', title: 'DHI Mortgage — Compliance/Ops', query: '"DHI Mortgage" compliance operations director manager contact email' },
  { industry: 'title_escrow', role: 'mortgage_lender', tier: 'primary', title: 'Neighbors Bank — Leadership', query: '"Neighbors Bank" mortgage director manager compliance contact email' },
  { industry: 'title_escrow', role: 'mortgage_lender', tier: 'primary', title: 'Flat Branch Mortgage — Leadership', query: '"Flat Branch Mortgage" director manager compliance contact email' },
  { industry: 'title_escrow', role: 'mortgage_lender', tier: 'primary', title: 'CrossCountry Mortgage — Compliance/Ops', query: '"CrossCountry Mortgage" OR "Cross Country Mortgage" compliance operations director contact email' },

  // DMS White-Label API targets — VP Product/Partnerships/BD at major document management platforms
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'DocuWare — VP Product/Partnerships', query: 'site:docuware.com OR "DocuWare" "VP Product" OR "VP Partnerships" OR "Business Development" director email contact' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'M-Files — VP Partnerships/Product', query: 'site:m-files.com OR "M-Files" "VP Partnerships" OR "VP Product" OR "Business Development" director email contact' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Laserfiche — VP Product/BD', query: 'site:laserfiche.com OR "Laserfiche" "VP Product" OR "Business Development" OR "VP Partnerships" director email contact' },
  { industry: 'legal', role: 'transact', tier: 'primary', title: 'NetDocuments — VP Product/Partnerships', query: 'site:netdocuments.com OR "NetDocuments" "VP Product" OR "VP Partnerships" OR "Business Development" director email contact' },
  { industry: 'legal', role: 'transact', tier: 'primary', title: 'iManage — VP Partnerships/BD', query: 'site:imanage.com OR "iManage" "VP Partnerships" OR "VP Product" OR "Business Development" director email contact' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'OpenText — BD Director/Partnerships', query: 'site:opentext.com OR "OpenText" "Business Development Director" OR "VP Partnerships" OR "Platform Partnerships" email contact' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'ShareFile (Citrix) — VP Product/Partnerships', query: '"ShareFile" OR "Citrix ShareFile" "VP Product" OR "VP Partnerships" OR "Business Development" director email contact' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Egnyte — VP Partnerships/BD', query: 'site:egnyte.com OR "Egnyte" "VP Partnerships" OR "VP Product" OR "Business Development" director email contact' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Box — VP Platform Partnerships', query: 'site:box.com "VP Platform" OR "VP Partnerships" OR "Platform Business Development" director email contact' },

  // Attorney General — home title theft prosecution
  { industry: 'government', role: 'ag_fraud', tier: 'primary',    title: 'Attorney General Consumer Protection', query: '"Attorney General" "consumer protection" OR "real estate fraud" OR "deed fraud" director counsel USA contact email site:*.gov' },
  { industry: 'government', role: 'ag_fraud', tier: 'primary',    title: 'State AG Real Estate Fraud Unit', query: '"Attorney General" "real estate fraud" OR "mortgage fraud" investigator OR director USA site:*.gov contact email' },

  // Tax Assessor — ownership data accuracy
  { industry: 'government', role: 'tax',      tier: 'primary',    title: 'County Tax Assessor',            query: '"County Tax Assessor" OR "County Assessor" contact email county USA site:*.gov' },
  { industry: 'government', role: 'tax',      tier: 'primary',    title: 'Property Appraiser Director',    query: '"Property Appraiser" director OR chief county USA contact email site:*.gov' },
  // ════════════════════════════════════════════════════════
  // UAE — Dubai Paperless Strategy 2026 + VARA compliance
  // Real Estate Developers (Big 10) + Automotive Conglomerates
  // ════════════════════════════════════════════════════════

  // Emaar Properties
  { industry: 'uae_realestate', role: 'uae_redev', tier: 'primary', title: 'CDO — Emaar Properties',               query: '"Emaar Properties" "Chief Digital Officer" OR "CDO" site:linkedin.com OR site:emaar.ae contact email' },
  { industry: 'uae_realestate', role: 'uae_reops', tier: 'primary', title: 'Head of Sales Operations — Emaar',      query: '"Emaar Properties" "Head of Sales Operations" OR "Sales Operations Director" site:linkedin.com contact email' },

  // DAMAC Properties
  { industry: 'uae_realestate', role: 'uae_redev', tier: 'primary', title: 'CTO — DAMAC Properties',                query: '"DAMAC Properties" "Chief Technology Officer" OR "CTO" site:linkedin.com OR site:damacproperties.com contact email' },
  { industry: 'uae_realestate', role: 'uae_recx',  tier: 'primary', title: 'Director of Customer Relations — DAMAC', query: '"DAMAC Properties" "Director of Customer Relations" OR "Customer Relations Director" site:linkedin.com contact email' },

  // Nakheel
  { industry: 'uae_realestate', role: 'uae_redev', tier: 'primary', title: 'Head of Digital Transformation — Nakheel', query: '"Nakheel" "Head of Digital Transformation" OR "Digital Transformation Director" site:linkedin.com OR site:nakheel.com contact email' },
  { industry: 'uae_realestate', role: 'uae_legal', tier: 'primary', title: 'VP Legal & Compliance — Nakheel',         query: '"Nakheel" "VP Legal" OR "Legal Compliance" OR "Head of Compliance" site:linkedin.com contact email' },

  // Dubai Holding
  { industry: 'uae_realestate', role: 'uae_redev', tier: 'primary', title: 'Chief Innovation Officer — Dubai Holding', query: '"Dubai Holding" "Chief Innovation Officer" OR "Head of Innovation" site:linkedin.com OR site:dubaiholding.com contact email' },
  { industry: 'uae_realestate', role: 'uae_reops', tier: 'primary', title: 'Head of Asset Management — Dubai Holding', query: '"Dubai Holding" "Head of Asset Management" OR "Asset Management Director" site:linkedin.com contact email' },

  // Meraas
  { industry: 'uae_realestate', role: 'uae_redev', tier: 'primary', title: 'Director of IT Infrastructure — Meraas',  query: '"Meraas" "IT Infrastructure" OR "Director of IT" site:linkedin.com OR site:meraas.com contact email' },
  { industry: 'uae_realestate', role: 'uae_reops', tier: 'primary', title: 'Head of Property Handover — Meraas',       query: '"Meraas" "Head of Property Handover" OR "Property Handover Manager" site:linkedin.com contact email' },

  // Sobha Realty
  { industry: 'uae_realestate', role: 'uae_redev', tier: 'primary', title: 'COO — Sobha Realty',                      query: '"Sobha Realty" "Chief Operations Officer" OR "COO" site:linkedin.com OR site:sobharealty.com contact email' },
  { industry: 'uae_realestate', role: 'uae_reops', tier: 'primary', title: 'Head of Quality Control — Sobha Realty',  query: '"Sobha Realty" "Head of Quality Control" OR "Quality Control Director" site:linkedin.com contact email' },

  // Deyaar
  { industry: 'uae_realestate', role: 'uae_redev', tier: 'primary', title: 'IT Director — Deyaar',                    query: '"Deyaar" "IT Director" OR "Head of IT" site:linkedin.com OR site:deyaar.ae contact email' },
  { industry: 'uae_realestate', role: 'uae_reops', tier: 'primary', title: 'Head of Community Management — Deyaar',   query: '"Deyaar" "Head of Community Management" OR "Community Management Director" site:linkedin.com contact email' },

  // Ellington Properties
  { industry: 'uae_realestate', role: 'uae_redev', tier: 'primary', title: 'Head of Technology — Ellington',          query: '"Ellington Properties" "Head of Technology" OR "Technology Director" site:linkedin.com OR site:ellingtonproperties.com contact email' },
  { industry: 'uae_realestate', role: 'uae_recx',  tier: 'primary', title: 'Director of Post-Sales — Ellington',      query: '"Ellington Properties" "Director of Post-Sales" OR "Post Sales Manager" site:linkedin.com contact email' },

  // Meydan Group
  { industry: 'uae_realestate', role: 'uae_redev', tier: 'primary', title: 'CIO — Meydan Group',                      query: '"Meydan Group" "Chief Information Officer" OR "CIO" site:linkedin.com OR site:meydan.ae contact email' },
  { industry: 'uae_realestate', role: 'uae_reops', tier: 'primary', title: 'Head of Real Estate — Meydan Group',       query: '"Meydan Group" "Head of Real Estate" OR "Real Estate Director" site:linkedin.com contact email' },

  // Binghatti
  { industry: 'uae_realestate', role: 'uae_redev', tier: 'primary', title: 'CEO / MD — Binghatti',                    query: '"Binghatti" "CEO" OR "Managing Director" site:linkedin.com OR site:binghatti.com contact email' },
  { industry: 'uae_realestate', role: 'uae_redev', tier: 'primary', title: 'Head of Digital Strategy — Binghatti',    query: '"Binghatti" "Head of Digital Strategy" OR "Digital Strategy Director" site:linkedin.com contact email' },

  // ── UAE Automotive Conglomerates
  { industry: 'uae_auto', role: 'uae_autodev', tier: 'primary', title: 'Head of Strategy & Transformation — Al-Futtaim', query: '"Al-Futtaim" OR "Al Futtaim" "Head of Strategy" OR "Transformation" automotive site:linkedin.com OR site:alfuttaim.com contact email' },
  { industry: 'uae_auto', role: 'uae_autodev', tier: 'primary', title: 'Director of Digital Experience — Al Tayer',       query: '"Al Tayer Motors" "Director of Digital Experience" OR "Digital Experience" site:linkedin.com contact email' },
  { industry: 'uae_auto', role: 'uae_autodev', tier: 'primary', title: 'CIO — AW Rostamani',                               query: '"AW Rostamani" "Chief Information Officer" OR "CIO" site:linkedin.com OR site:awrostamani.com contact email' },
  { industry: 'uae_auto', role: 'uae_autodev', tier: 'primary', title: 'Head of Business Development — Gargash Group',    query: '"Gargash Group" OR "Gargash Enterprises" "Head of Business Development" site:linkedin.com contact email' },
  { industry: 'uae_auto', role: 'uae_autodev', tier: 'primary', title: 'Director of Operations — Al Habtoor Motors',      query: '"Al Habtoor Motors" "Director of Operations" OR "Operations Director" site:linkedin.com contact email' },

  // ════════════════════════════════════════════════════════
  // ENTERPRISE INSURANCE — Claims, SIU, Fraud directors
  // Strategy: industry press, regulatory filings, conference bios
  // ════════════════════════════════════════════════════════
  // Allianz — target Allianz Technology (internal tech wing) + Global P&C Claims
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Director — Allianz Technology Digital Claims',  query: '"Allianz Technology" "Director" OR "Head" "Claims" OR "Digital" OR "P&C" email contact site:linkedin.com' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Head of P&C — Allianz Global Claims',          query: '"Allianz" "Global P&C" OR "Property Casualty" "Head" OR "Director" email contact site:linkedin.com OR site:allianz.com/news' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Innovation Lead — Allianz Technology',         query: '"Allianz Technology" "blockchain" OR "digital property" OR "innovation" director speaker email conference' },

  // AXA — target AXA Next (innovation) + AXA Group Operations
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Director — AXA Next Blockchain Innovation',    query: '"AXA Next" "Director" OR "Head" email contact site:linkedin.com OR site:axa.com/en/newsroom' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Head of Operations — AXA Group Operations',   query: '"AXA Group Operations" "Director" OR "Head" OR "VP" email contact site:linkedin.com' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Blockchain Lead — AXA parametric insurance',  query: '"AXA" "blockchain" OR "parametric" OR "smart contract" "director" OR "head" speaker email conference bio' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Claims Director — AXA',                       query: '"AXA" "Head of Claims" OR "Claims Director" contact email site:linkedin.com OR site:axa.com' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Claims Director — Zurich Insurance', query: '"Zurich Insurance" "Director" "Claims" OR "Head of Claims" email contact site:linkedin.com OR site:zurich.com' },
  // AIG — target Commercial Underwriting + Legal Operations
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Director — AIG Commercial Underwriting',       query: '"AIG" "Commercial Underwriting" "Director" OR "VP" OR "Head" email contact site:linkedin.com' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'VP Legal Operations — AIG',                   query: '"AIG" "Legal Operations" OR "Legal Director" OR "General Counsel" email contact site:linkedin.com OR site:aig.com/about' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Real Estate Risk — AIG Global',               query: '"AIG" "global real estate" OR "complex risk" OR "corporate insurance" director speaker email conference bio' },

  // Chubb — target North American/Global Claims + Information Security
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Claims Director — Chubb North America',       query: '"Chubb" "North America" "Claims Director" OR "Head of Claims" OR "VP Claims" email contact site:linkedin.com' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'CISO / InfoSec — Chubb Global',               query: '"Chubb" "Information Security" OR "CISO" OR "Cybersecurity" director email contact site:linkedin.com OR site:chubb.com' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Property Claims — Chubb luxury real estate',  query: '"Chubb" "high value" OR "luxury" OR "real estate title" "claims" director speaker email conference bio' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Claims Director — Travelers',        query: '"Travelers Insurance" "Claims Director" OR "VP Claims" OR "Head of Claims" contact email site:linkedin.com' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'SIU Director — Liberty Mutual',      query: '"Liberty Mutual" "SIU" OR "Special Investigations" OR "Fraud Director" director contact email site:linkedin.com' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'SIU Director — State Farm',          query: '"State Farm" "Special Investigations" OR "SIU" OR "Fraud" director email contact site:linkedin.com' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'SIU Director — Progressive',         query: '"Progressive Insurance" "Special Investigations" OR "SIU Director" OR "Fraud" director email contact site:linkedin.com' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Governance Director — Marsh McLennan', query: '"Marsh McLennan" "Risk" OR "Governance" OR "Compliance" director email contact site:linkedin.com OR site:marshmclennan.com' },

  // ════════════════════════════════════════════════════════
  // GLOBAL LAW FIRMS — eDiscovery, Litigation Support, Innovation
  // Strategy: firm websites publish attorney emails directly
  // ════════════════════════════════════════════════════════
  { industry: 'global_legal', role: 'global_law_firm', tier: 'primary', title: 'eDiscovery Director — Kirkland & Ellis',        query: 'site:kirkland.com "eDiscovery" OR "Litigation Support" OR "Legal Technology" director email' },
  { industry: 'global_legal', role: 'global_law_firm', tier: 'primary', title: 'Litigation Support — Latham & Watkins',         query: 'site:lw.com "eDiscovery" OR "Litigation Support" OR "Legal Operations" email contact' },
  { industry: 'global_legal', role: 'global_law_firm', tier: 'primary', title: 'Innovation Director — Baker McKenzie',          query: 'site:bakermckenzie.com "Innovation" OR "Legal Technology" OR "Knowledge Management" director email' },
  { industry: 'global_legal', role: 'global_law_firm', tier: 'primary', title: 'eDiscovery Director — DLA Piper',              query: 'site:dlapiper.com "eDiscovery" OR "Litigation Support" OR "Legal Operations" email contact' },
  { industry: 'global_legal', role: 'global_law_firm', tier: 'primary', title: 'Innovation Director — Clifford Chance',        query: 'site:cliffordchance.com "Innovation" OR "Legal Technology" OR "Knowledge" director manager email' },
  { industry: 'global_legal', role: 'global_law_firm', tier: 'primary', title: 'Legal Tech Director — Freshfields',            query: 'site:freshfields.com "Legal Technology" OR "Innovation" OR "eDiscovery" director email contact' },
  { industry: 'global_legal', role: 'global_law_firm', tier: 'primary', title: 'Innovation — Allen Overy Shearman',            query: 'site:aoshearman.com "Innovation" OR "Legal Technology" OR "Knowledge" email contact director' },
  { industry: 'global_legal', role: 'global_law_firm', tier: 'primary', title: 'eDiscovery Director — Skadden',               query: 'site:skadden.com "eDiscovery" OR "Litigation Technology" OR "Legal Operations" email director' },
  { industry: 'global_legal', role: 'global_law_firm', tier: 'primary', title: 'Legal Tech — Hogan Lovells',                  query: 'site:hoganlovells.com "Legal Technology" OR "eDiscovery" OR "Innovation" director email' },
  { industry: 'global_legal', role: 'global_law_firm', tier: 'primary', title: 'Knowledge Director — Jones Day',              query: 'site:jonesday.com "Knowledge Management" OR "Legal Operations" OR "Innovation" director email' },
  { industry: 'global_legal', role: 'global_law_firm', tier: 'primary', title: 'eDiscovery — White & Case',                   query: 'site:whitecase.com "eDiscovery" OR "Litigation Support" OR "Legal Technology" director email' },
  { industry: 'global_legal', role: 'global_law_firm', tier: 'primary', title: 'Innovation — Norton Rose Fulbright',          query: 'site:nortonrosefulbright.com "Innovation" OR "Legal Technology" OR "Knowledge" director email' },
  { industry: 'global_legal', role: 'global_law_firm', tier: 'primary', title: 'eDiscovery — Gibson Dunn',                    query: 'site:gibsondunn.com "eDiscovery" OR "Litigation Support" OR "Legal Operations" email contact' },
  { industry: 'global_legal', role: 'global_law_firm', tier: 'primary', title: 'Innovation — Linklaters',                     query: 'site:linklaters.com "Innovation" OR "Legal Technology" OR "Knowledge" director email' },
  { industry: 'global_legal', role: 'global_law_firm', tier: 'primary', title: 'eDiscovery — Sidley Austin',                  query: 'site:sidley.com "eDiscovery" OR "Litigation Technology" OR "Legal Operations" email director' },

  // ════════════════════════════════════════════════════════
  // GOVERNMENT REGULATORS — Enforcement, Records, Digital Evidence
  // Strategy: .gov sites publish staff directories with emails
  // ════════════════════════════════════════════════════════
  { industry: 'gov_regulator', role: 'gov_regulator', tier: 'primary', title: 'Enforcement Director — SEC',              query: 'site:sec.gov "Director" "Enforcement" OR "Digital Evidence" OR "Records" email contact staff' },
  { industry: 'gov_regulator', role: 'gov_regulator', tier: 'primary', title: 'Records Director — IRS',                  query: 'site:irs.gov "Director" "Records" OR "Information Governance" OR "Compliance" email contact' },
  { industry: 'gov_regulator', role: 'gov_regulator', tier: 'primary', title: 'Enforcement — FCA UK',                    query: 'site:fca.org.uk "Director" "Enforcement" OR "Compliance" OR "Records" email contact staff' },
  { industry: 'gov_regulator', role: 'gov_regulator', tier: 'primary', title: 'Records — HMRC',                          query: 'site:gov.uk "HMRC" "Director" "Records Management" OR "Information Governance" email contact' },
  { industry: 'gov_regulator', role: 'gov_regulator', tier: 'primary', title: 'Investigations Director — OLAF',          query: 'site:ec.europa.eu "OLAF" OR "anti-fraud" "Director" "Investigations" email contact' },
  { industry: 'gov_regulator', role: 'gov_regulator', tier: 'primary', title: 'Cybersecurity Director — NIST',           query: 'site:nist.gov "Director" "Cybersecurity" OR "Digital" OR "Records" email contact staff' },
  { industry: 'gov_regulator', role: 'gov_regulator', tier: 'primary', title: 'Information Assurance — DHS',             query: 'site:dhs.gov "Director" "Information Assurance" OR "Records" OR "Digital Evidence" email contact' },
  { industry: 'gov_regulator', role: 'gov_regulator', tier: 'primary', title: 'Enforcement — MAS Singapore',             query: 'site:mas.gov.sg "Director" "Enforcement" OR "Compliance" OR "Records" email contact staff' },
  { industry: 'gov_regulator', role: 'gov_regulator', tier: 'primary', title: 'Enforcement — ASIC Australia',            query: 'site:asic.gov.au "Director" "Enforcement" OR "Records" OR "Compliance" email contact staff' },

  // ════════════════════════════════════════════════════════
  // PHARMA / LIFE SCIENCES — Regulatory, Compliance, Clinical Data
  // Strategy: FDA submissions, conference speaker bios, press releases
  // ════════════════════════════════════════════════════════
  { industry: 'pharma', role: 'pharma_cco', tier: 'primary', title: 'Regulatory Director — Pfizer',          query: '"Pfizer" "Director" "Regulatory Affairs" OR "Regulatory Compliance" email contact site:linkedin.com OR site:pfizer.com' },
  { industry: 'pharma', role: 'pharma_cco', tier: 'primary', title: 'Compliance Director — J&J',             query: '"Johnson Johnson" OR "J&J" "Director" "Compliance" OR "Regulatory" OR "Clinical Data" email contact site:linkedin.com' },
  { industry: 'pharma', role: 'pharma_cco', tier: 'primary', title: 'Compliance Director — Novartis',        query: '"Novartis" "Director" "Compliance" OR "Clinical Data Integrity" email contact site:linkedin.com OR site:novartis.com' },
  { industry: 'pharma', role: 'pharma_cco', tier: 'primary', title: 'Compliance Director — Roche',           query: '"Roche" "Director" "Compliance" OR "Regulatory Affairs" email contact site:linkedin.com OR site:roche.com' },
  { industry: 'pharma', role: 'pharma_cco', tier: 'primary', title: 'Regulatory Director — Merck',           query: '"Merck" "Director" "Regulatory Affairs" OR "Information Governance" email contact site:linkedin.com' },
  { industry: 'pharma', role: 'pharma_cco', tier: 'primary', title: 'Clinical Ops Director — AstraZeneca',   query: '"AstraZeneca" "Director" "Clinical Operations" OR "Clinical Data" OR "Compliance" email site:linkedin.com' },
  { industry: 'pharma', role: 'pharma_cco', tier: 'primary', title: 'Data Integrity Director — GSK',         query: '"GSK" "Director" "Data Integrity" OR "Compliance" OR "Regulatory" email contact site:linkedin.com OR site:gsk.com' },
  { industry: 'pharma', role: 'pharma_cco', tier: 'primary', title: 'Compliance Director — Bayer',           query: '"Bayer" "Director" "Clinical Compliance" OR "Regulatory" OR "Data Integrity" email site:linkedin.com' },
  { industry: 'pharma', role: 'pharma_cco', tier: 'primary', title: 'Clinical Director — AbbVie',            query: '"AbbVie" "Director" "Clinical Operations" OR "Compliance" OR "Regulatory Affairs" email site:linkedin.com' },
  { industry: 'pharma', role: 'pharma_cco', tier: 'primary', title: 'Compliance Director — Eli Lilly',       query: '"Eli Lilly" OR "Lilly" "Director" "Compliance" OR "Clinical Records" email contact site:linkedin.com' },

  // ════════════════════════════════════════════════════════
  // HEALTHCARE SYSTEMS — HIM, Privacy, Compliance Directors
  // Strategy: hospital websites publish department contacts
  // ════════════════════════════════════════════════════════
  { industry: 'healthcare', role: 'healthcare', tier: 'primary', title: 'HIM Director — Mayo Clinic',             query: 'site:mayoclinic.org "Director" "Health Information" OR "Medical Records" OR "HIM" email contact' },
  { industry: 'healthcare', role: 'healthcare', tier: 'primary', title: 'HIM Director — Cleveland Clinic',        query: 'site:clevelandclinic.org "Director" "Health Information" OR "Medical Records" OR "Compliance" email' },
  { industry: 'healthcare', role: 'healthcare', tier: 'primary', title: 'Privacy Officer — Kaiser Permanente',    query: 'site:kaiserpermanente.org "Privacy Officer" OR "Information Governance" OR "HIM Director" email contact' },
  { industry: 'healthcare', role: 'healthcare', tier: 'primary', title: 'HIM Director — Mass General Brigham',   query: 'site:massgeneralbrigham.org "Health Information" OR "Medical Records" OR "HIM" director email' },
  { industry: 'healthcare', role: 'healthcare', tier: 'primary', title: 'Compliance — Johns Hopkins',             query: 'site:hopkinsmedicine.org "Research Compliance" OR "Compliance Director" OR "HIM" email contact' },
  { industry: 'healthcare', role: 'healthcare', tier: 'primary', title: 'IG Lead — NHS England',                 query: 'site:england.nhs.uk "Information Governance" OR "Digital Records" director email contact staff' },
  { industry: 'healthcare', role: 'healthcare', tier: 'primary', title: 'HIM Director — SingHealth',              query: 'site:singhealth.com.sg "Health Information" OR "Medical Records" OR "HIM" director email contact' },

  // ════════════════════════════════════════════════════════
  // CONSTRUCTION & ENGINEERING — Claims, Project Controls, Contract Directors
  // Strategy: project delivery firms list contacts in project profiles
  // ════════════════════════════════════════════════════════
  { industry: 'construction', role: 'lien', tier: 'primary', title: 'Contract Manager — Bechtel',              query: 'site:bechtel.com "Contract Manager" OR "Project Controls" OR "Claims" director email contact' },
  { industry: 'construction', role: 'lien', tier: 'primary', title: 'Claims Manager — Fluor',                  query: 'site:fluor.com "Claims Manager" OR "Project Director" OR "Contract" director email contact' },
  { industry: 'construction', role: 'lien', tier: 'primary', title: 'Program Director — Jacobs Engineering',   query: 'site:jacobs.com "Program Director" OR "Project Controls" OR "Document Control" email contact' },
  { industry: 'construction', role: 'lien', tier: 'primary', title: 'Document Control — Turner Construction',  query: 'site:turnerconstruction.com "Document Control" OR "Project Controls" OR "Contract" director email' },
  { industry: 'construction', role: 'lien', tier: 'primary', title: 'Contracts Director — Vinci',              query: 'site:vinci.com "Contracts Director" OR "Project Controls" OR "Claims" email contact director' },
  { industry: 'construction', role: 'lien', tier: 'primary', title: 'Project Controls — AECOM',               query: 'site:aecom.com "Project Controls" OR "Contract Management" OR "Claims" director email contact' },
  { industry: 'construction', role: 'lien', tier: 'primary', title: 'Project Controls — WSP Global',          query: 'site:wsp.com "Project Controls" OR "Contract Management" director email contact' },

  // ════════════════════════════════════════════════════════
  // REAL ESTATE — Transaction, Compliance, Asset Directors
  // ════════════════════════════════════════════════════════
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Transaction Director — CBRE',           query: 'site:cbre.com "Transaction Director" OR "Compliance" OR "Lease Administration" director email contact' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Transaction Manager — JLL',             query: 'site:jll.com "Transaction" OR "Lease Administration" OR "Compliance" director email contact' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Lease Director — Cushman & Wakefield',  query: 'site:cushmanwakefield.com "Lease Administration" OR "Transaction" OR "Compliance" director email' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Compliance Director — Zillow',          query: 'site:zillow.com "Compliance" OR "Data Integrity" OR "Operations" director email contact' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Asset Manager — Prologis',              query: 'site:prologis.com "Asset Manager" OR "Lease" OR "Compliance" director email contact' },

  // ════════════════════════════════════════════════════════
  // UNIVERSITIES — Research Integrity, Compliance, Research Office
  // Strategy: university staff directories are publicly searchable
  // ════════════════════════════════════════════════════════
  { industry: 'university_research', role: 'university_research', tier: 'primary', title: 'Research Integrity — Harvard',         query: 'site:harvard.edu "Research Integrity" OR "Research Compliance" director officer email contact staff' },
  { industry: 'university_research', role: 'university_research', tier: 'primary', title: 'Research Compliance — MIT',             query: 'site:mit.edu "Research Compliance" OR "Research Administration" director email contact staff' },
  { industry: 'university_research', role: 'university_research', tier: 'primary', title: 'Research Compliance — Stanford',        query: 'site:stanford.edu "Research Compliance" OR "Research Integrity" director officer email contact' },
  { industry: 'university_research', role: 'university_research', tier: 'primary', title: 'Research Governance — Oxford',          query: 'site:ox.ac.uk "Research Integrity" OR "Research Governance" OR "Research Services" director email' },
  { industry: 'university_research', role: 'university_research', tier: 'primary', title: 'Research Integrity — Cambridge',        query: 'site:cam.ac.uk "Research Integrity" OR "Research Governance" director officer email contact' },
  { industry: 'university_research', role: 'university_research', tier: 'primary', title: 'Research Compliance — UC Berkeley',    query: 'site:berkeley.edu "Research Compliance" OR "Research Administration" director email contact' },
  { industry: 'university_research', role: 'university_research', tier: 'primary', title: 'Research Integrity — ETH Zurich',      query: 'site:ethz.ch "Research Integrity" OR "Research Compliance" OR "Research Governance" director email' },
  { industry: 'university_research', role: 'university_research', tier: 'primary', title: 'Research Governance — NUS Singapore',  query: 'site:nus.edu.sg "Research Integrity" OR "Research Compliance" director officer email contact' },
  { industry: 'university_research', role: 'university_research', tier: 'primary', title: 'Research Compliance — U Melbourne',    query: 'site:unimelb.edu.au "Research Governance" OR "Research Integrity" director email contact staff' },
  { industry: 'university_research', role: 'university_research', tier: 'primary', title: 'Research Integrity — U Toronto',       query: 'site:utoronto.ca "Research Integrity" OR "Research Ethics" director email contact staff' },

  // ════════════════════════════════════════════════════════
  // GOVERNMENT ARCHIVES — Records Directors, Digital Preservation
  // Strategy: government websites always list staff with emails
  // ════════════════════════════════════════════════════════
  { industry: 'intl_archives', role: 'intl_archives', tier: 'primary', title: 'Records Director — NARA',                query: 'site:archives.gov "Director" "Records" OR "Digital Preservation" OR "Information Governance" email contact staff' },
  { industry: 'intl_archives', role: 'intl_archives', tier: 'primary', title: 'Director — National Archives UK',         query: 'site:nationalarchives.gov.uk "Director" "Records" OR "Digital Preservation" OR "Information" email contact' },
  { industry: 'intl_archives', role: 'intl_archives', tier: 'primary', title: 'Director — National Archives Australia',  query: 'site:naa.gov.au "Director" "Records" OR "Digital Preservation" OR "Information Management" email contact' },
  { industry: 'intl_archives', role: 'intl_archives', tier: 'primary', title: 'Director — Library and Archives Canada',  query: 'site:bac-lac.gc.ca OR site:lac-bac.gc.ca "Director" "Records" OR "Information Management" email contact' },
  { industry: 'intl_archives', role: 'intl_archives', tier: 'primary', title: 'Director — National Archives Singapore',  query: 'site:nas.gov.sg "Director" "Archives" OR "Digital Preservation" email contact staff' },

  // ════════════════════════════════════════════════════════
  // SINGAPORE LAND AUTHORITY — named contacts
  // ════════════════════════════════════════════════════════
  { industry: 'gov_regulator', role: 'gov_regulator', tier: 'primary', title: 'Calvin Phua — Singapore Land Authority CEO',
    query: '"Calvin Phua" "Singapore Land Authority" email contact OR speaker OR conference OR interview' },
  { industry: 'gov_regulator', role: 'gov_regulator', tier: 'primary', title: 'Yeoh Oon Jin — Singapore Land Authority Chairman',
    query: '"Yeoh Oon Jin" "Singapore Land Authority" email contact OR speaker OR conference OR interview' },
  { industry: 'gov_regulator', role: 'gov_regulator', tier: 'primary', title: 'Registrar of Titles — Singapore Land Authority',
    query: '"Singapore Land Authority" "Registrar" "Titles" OR "Deeds" email contact site:sla.gov.sg' },

  // ════════════════════════════════════════════════════════
  // DUBAI LAND DEPARTMENT — named contacts
  // ════════════════════════════════════════════════════════
  { industry: 'gov_regulator', role: 'gov_regulator', tier: 'primary', title: 'Majid Al Marri — Dubai Land Dept CEO Registration',
    query: '"Majid" "Al Marri" "Dubai Land" email contact OR speaker OR conference OR interview' },
  { industry: 'gov_regulator', role: 'gov_regulator', tier: 'primary', title: 'Hend Al Marri — Dubai Land Department CEO',
    query: '"Hend Al Marri" "Dubai Land" email contact OR speaker OR conference OR interview' },
  { industry: 'gov_regulator', role: 'gov_regulator', tier: 'primary', title: 'Majida Ali Rashid — Dubai Land Dept Development CEO',
    query: '"Majida Ali Rashid" "Dubai Land" email contact OR speaker OR conference OR interview' },
  { industry: 'gov_regulator', role: 'gov_regulator', tier: 'primary', title: 'Blockchain/Innovation Director — Dubai Land Department',
    query: 'site:dubailand.gov.ae "blockchain" OR "digital" OR "innovation" director email contact' },

  // ════════════════════════════════════════════════════════
  // HM LAND REGISTRY — enhanced role-based named searches
  // ════════════════════════════════════════════════════════
  { industry: 'gov_regulator', role: 'gov_regulator', tier: 'primary', title: 'Chief Executive — HM Land Registry',
    query: '"HM Land Registry" "Chief Executive" email contact OR speaker OR conference OR interview' },
  { industry: 'gov_regulator', role: 'gov_regulator', tier: 'primary', title: 'Chief Digital & Data Officer — HM Land Registry',
    query: '"HM Land Registry" "Chief Digital" OR "Chief Data Officer" OR "Director Digital" email contact site:gov.uk OR site:linkedin.com' },
  { industry: 'gov_regulator', role: 'gov_regulator', tier: 'primary', title: 'Director Land Registration — HM Land Registry',
    query: '"HM Land Registry" "Director" "Land Registration" OR "Digital Services" OR "Transformation" email contact site:gov.uk' },

  // ════════════════════════════════════════════════════════
  // BAKER McKENZIE — named contact
  // ════════════════════════════════════════════════════════
  { industry: 'global_legal', role: 'global_law_firm', tier: 'primary', title: 'Ben Weinberger — Baker McKenzie Innovation',
    query: '"Ben Weinberger" "Baker McKenzie" email contact OR speaker OR conference OR interview OR podcast' },

  // ════════════════════════════════════════════════════════
  // DLA PIPER — named contact
  // ════════════════════════════════════════════════════════
  { industry: 'global_legal', role: 'global_law_firm', tier: 'primary', title: 'David Cunningham — DLA Piper Innovation Technology',
    query: '"David Cunningham" "DLA Piper" email contact OR speaker OR conference OR interview OR podcast' },

  // ════════════════════════════════════════════════════════
  // AMROCK / ROCKET MORTGAGE — named contacts
  // ════════════════════════════════════════════════════════
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Nicole Beattie — Amrock CEO',
    query: '"Nicole Beattie" "Amrock" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Shawn Malhotra — Rocket Mortgage CTO',
    query: '"Shawn Malhotra" "Rocket" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Heather Lovier — Amrock COO',
    query: '"Heather Lovier" "Amrock" email contact OR speaker OR conference OR interview' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Jay Jones — Rocket Chief Servicing Officer',
    query: '"Jay Jones" "Rocket" "Servicing" email contact OR speaker OR conference OR interview' },

  // ════════════════════════════════════════════════════════
  // BIG FOUR ACCOUNTING — Forensic, Digital Risk, RegTech buyers
  // These firms investigate fraud and document disputes daily
  // ════════════════════════════════════════════════════════
  { industry: 'legal', role: 'legal', tier: 'primary', title: 'Forensic Services Partner — Deloitte',
    query: '"Deloitte" "Forensic Services" OR "Digital Risk" OR "Regulatory Technology" partner director email contact site:linkedin.com OR site:deloitte.com' },
  { industry: 'legal', role: 'legal', tier: 'primary', title: 'Technology Risk Leader — Deloitte',
    query: '"Deloitte" "Technology Risk" OR "Digital Forensics" OR "Document Intelligence" leader email contact site:linkedin.com' },
  { industry: 'legal', role: 'legal', tier: 'primary', title: 'Forensic Services Partner — PwC',
    query: '"PwC" "Forensic Services" OR "Digital Risk" OR "Regulatory Technology" partner director email contact site:linkedin.com OR site:pwc.com' },
  { industry: 'legal', role: 'legal', tier: 'primary', title: 'Technology Risk Leader — PwC',
    query: '"PwC" "Technology Risk" OR "Digital Forensics" OR "Document Intelligence" leader email contact site:linkedin.com' },
  { industry: 'legal', role: 'legal', tier: 'primary', title: 'Forensic Services Partner — EY',
    query: '"EY" OR "Ernst Young" "Forensic" OR "Digital Risk" OR "Fraud Investigation" partner director email contact site:linkedin.com OR site:ey.com' },
  { industry: 'legal', role: 'legal', tier: 'primary', title: 'Technology Risk Leader — EY',
    query: '"EY" OR "Ernst Young" "Technology Risk" OR "Digital Forensics" OR "RegTech" leader email contact site:linkedin.com' },
  { industry: 'legal', role: 'legal', tier: 'primary', title: 'Forensic Services Partner — KPMG',
    query: '"KPMG" "Forensic Services" OR "Digital Risk" OR "Regulatory Technology" partner director email contact site:linkedin.com OR site:kpmg.com' },
  { industry: 'legal', role: 'legal', tier: 'primary', title: 'Technology Risk Leader — KPMG',
    query: '"KPMG" "Technology Risk" OR "Digital Forensics" OR "Document Intelligence" leader email contact site:linkedin.com' },

  // ════════════════════════════════════════════════════════
  // NAMED TARGETS — real identified decision-makers
  // Strategy: search by full name + company for published email
  // across conference bios, bylines, podcasts, patent filings
  // ════════════════════════════════════════════════════════

  // ALLIANZ — named contacts
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Iain Briggs — Allianz Technology',
    query: '"Iain Briggs" "Allianz" email contact OR speaker OR interview OR podcast' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Melissa Hill — Allianz Claims Transformation',
    query: '"Melissa Hill" "Allianz" email contact OR speaker OR conference OR interview' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Thomas Sepp — Allianz Claims Leadership',
    query: '"Thomas Sepp" "Allianz" email contact OR speaker OR interview' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Nick Kelsall — Allianz Digital Fraud',
    query: '"Nick Kelsall" "Allianz" email contact OR speaker OR conference OR interview' },
  // Scrape the Allianz press release pages directly — PR contacts listed at bottom
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'PR Contact — Allianz Commercial NA Claims',
    query: 'site:commercial.allianz.com "new-na-head-of-claims" email contact press' },

  // AXA — named contacts
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Matthieu Caillat — AXA Digital Transformation',
    query: '"Matthieu Caillat" "AXA" email contact OR speaker OR conference OR interview' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Guillaume Borie — AXA Technology',
    query: '"Guillaume Borie" "AXA" email contact OR speaker OR interview OR podcast' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Karima Silvent — AXA Compliance Governance',
    query: '"Karima Silvent" "AXA" email contact OR speaker OR conference OR interview' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Francoise Gilles — AXA Chief Risk Officer',
    query: '"Francoise Gilles" OR "Françoise Gilles" "AXA" email contact OR speaker OR conference OR interview' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Helen Browne — AXA Legal Governance',
    query: '"Helen Browne" "AXA" email contact OR speaker OR conference OR interview' },

  // AIG — named contacts
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Roshan Navagamuwa — AIG CIO',
    query: '"Roshan Navagamuwa" "AIG" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Scott Hallworth — AIG Digital Transformation',
    query: '"Scott Hallworth" "AIG" email contact OR speaker OR conference OR interview' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Chris Schaper — AIG Risk Management',
    query: '"Chris Schaper" "AIG" email contact OR speaker OR conference OR interview' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Christopher Flatt — AIG Commercial Underwriting',
    query: '"Christopher Flatt" "AIG" email contact OR speaker OR conference OR interview' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Jon Hancock — AIG Claims Global',
    query: '"Jon Hancock" "AIG" email contact OR speaker OR conference OR interview' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Rose Marie Glazer — AIG Legal Operations',
    query: '"Rose Marie Glazer" "AIG" email contact OR speaker OR conference OR interview' },

  // CHUBB — named contacts
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Michael Jones — Chubb Global Operations Technology',
    query: '"Michael Jones" "Chubb" "Operations" OR "Technology" email contact OR speaker OR conference OR interview' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Gordon Mackechnie — Chubb Global Head of Technology',
    query: '"Gordon Mackechnie" "Chubb" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Kevin Rampe — Chubb Global Head of Claims',
    query: '"Kevin Rampe" "Chubb" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Sean Ringsted — Chubb Analytics Fraud AI',
    query: '"Sean Ringsted" "Chubb" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Frances OBrien — Chubb Risk',
    query: '"Frances" "OBrien" "Chubb" email contact OR speaker OR conference OR interview' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Joseph Wayland — Chubb Legal Governance',
    query: '"Joseph Wayland" "Chubb" email contact OR speaker OR conference OR interview' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Dennis Quinn — Chubb Compliance',
    query: '"Dennis Quinn" "Chubb" email contact OR speaker OR conference OR interview' },
  // Scrape Chubb press release directly for PR contact email
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'PR Contact — Chubb Kevin Rampe announcement',
    query: 'site:news.chubb.com "Kevin-Rampe-Global-Head-of-Claims" email contact press media' },

  // ════════════════════════════════════════════════════════
  // TITLE INSURANCE — First American Financial
  // ════════════════════════════════════════════════════════
  { industry: 'title_escrow', role: 'title_closer', tier: 'primary', title: 'Paul Hurst — First American CIO',
    query: '"Paul Hurst" "First American" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'title_escrow', role: 'title_closer', tier: 'primary', title: 'Mark Seaton — First American CEO',
    query: '"Mark Seaton" "First American" email contact OR speaker OR conference OR interview OR podcast' },

  // TITLE INSURANCE — Stewart Title
  // ════════════════════════════════════════════════════════
  { industry: 'title_escrow', role: 'title_closer', tier: 'primary', title: 'Jonathan Snyman — Stewart Title Compliance',
    query: '"Jonathan Snyman" "Stewart" email contact OR speaker OR conference OR interview' },
  { industry: 'title_escrow', role: 'title_closer', tier: 'primary', title: 'Karen Decker — Stewart Title Underwriting',
    query: '"Karen Decker" "Stewart Title" email contact OR speaker OR conference OR interview' },
  { industry: 'title_escrow', role: 'title_closer', tier: 'primary', title: 'Frank Maggisano — Stewart Title Claims',
    query: '"Frank Maggisano" "Stewart" email contact OR speaker OR conference OR interview' },
  { industry: 'title_escrow', role: 'title_closer', tier: 'primary', title: 'Ben Gunning — Stewart Title Technology',
    query: '"Ben Gunning" "Stewart" email contact OR speaker OR conference OR interview' },
  { industry: 'title_escrow', role: 'title_closer', tier: 'primary', title: 'Brad Rable — Stewart Title CIO',
    query: '"Brad Rable" "Stewart" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'title_escrow', role: 'title_closer', tier: 'primary', title: 'Louis Pontani — Stewart Title Operations',
    query: '"Louis Pontani" "Stewart" email contact OR speaker OR conference OR interview' },
  // Scrape Stewart leadership pages directly
  { industry: 'title_escrow', role: 'title_closer', tier: 'primary', title: 'Leadership emails — Stewart Title Canada',
    query: 'site:stewart.ca "leadership-team" email contact' },
  { industry: 'title_escrow', role: 'title_closer', tier: 'primary', title: 'Leadership emails — Stewart Title US',
    query: 'site:investors.stewart.com "executive-team" email contact' },

  // ════════════════════════════════════════════════════════
  // COMMERCIAL REAL ESTATE — CBRE
  // ════════════════════════════════════════════════════════
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Anuj Kadyan — CBRE CTO Transformation',
    query: '"Anuj Kadyan" "CBRE" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Sandeep Dave — CBRE Chief Digital Officer',
    query: '"Sandeep Dave" OR "Sandeep Davé" "CBRE" email contact OR speaker OR conference OR interview' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Umesh Patel — CBRE CIO',
    query: '"Umesh Patel" "CBRE" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Alison Bell — CBRE Global Digital Strategy',
    query: '"Alison Bell" "CBRE" email contact OR speaker OR conference OR interview' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Ampily Vijay — CBRE CDTO Operations',
    query: '"Ampily Vijay" "CBRE" email contact OR speaker OR conference OR interview' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Chad Doellinger — CBRE Legal Governance',
    query: '"Chad Doellinger" "CBRE" email contact OR speaker OR conference OR interview' },
  // Scrape CBRE leadership pages
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Leadership emails — CBRE Executive',
    query: 'site:ir.cbre.com "executive-leadership" email contact' },

  // ════════════════════════════════════════════════════════
  // COMMERCIAL REAL ESTATE — JLL
  // ════════════════════════════════════════════════════════
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'George Thomas — JLL Global CIO',
    query: '"George Thomas" "JLL" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Yao Morin — JLL CTO',
    query: '"Yao Morin" "JLL" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Mihir Shah — JLL Technologies CEO',
    query: '"Mihir Shah" "JLL" OR "JLL Technologies" email contact OR speaker OR conference OR interview' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Alan Tse — JLL Chief Legal Officer',
    query: '"Alan Tse" "JLL" email contact OR speaker OR conference OR interview' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Sharad Rastogi — JLL Technology Transformation',
    query: '"Sharad Rastogi" "JLL" email contact OR speaker OR conference OR interview' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Daniel Russo — JLL PropTech',
    query: '"Daniel Russo" "JLL" email contact OR speaker OR conference OR interview' },
  // Scrape JLL leadership pages
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Leadership emails — JLL Global',
    query: 'site:jll.com "leadership" "bio-leader" email contact' },

  // ════════════════════════════════════════════════════════
  // TITLE INSURANCE — Fidelity National Financial (named — A+ priority)
  // Jason Nadeau = CDO + Chief AI Officer — highest priority in entire list
  // ════════════════════════════════════════════════════════
  { industry: 'title_escrow', role: 'title_closer', tier: 'primary', title: 'Jason Nadeau — FNF Chief Digital & AI Officer',
    query: '"Jason Nadeau" "Fidelity National" OR "FNF" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'title_escrow', role: 'title_closer', tier: 'primary', title: 'John Crowley — FNF CIO',
    query: '"John Crowley" "Fidelity National" OR "FNF" email contact OR speaker OR conference OR interview' },
  { industry: 'title_escrow', role: 'title_closer', tier: 'primary', title: 'Patrick Rhodin — FNF Chief Risk Officer',
    query: '"Patrick Rhodin" "Fidelity National" OR "FNF" email contact OR speaker OR conference OR interview' },
  { industry: 'title_escrow', role: 'title_closer', tier: 'primary', title: 'Peter Sadowski — FNF Chief Legal Officer',
    query: '"Peter Sadowski" "Fidelity National" OR "FNF" email contact OR speaker OR conference OR interview' },
  { industry: 'title_escrow', role: 'title_closer', tier: 'primary', title: 'Paul Perez — FNF Chief Compliance Officer',
    query: '"Paul Perez" "Fidelity National" OR "FNF" email contact OR speaker OR conference OR interview' },
  { industry: 'title_escrow', role: 'title_closer', tier: 'primary', title: 'Katie Schmidt — FNF Chief Regulatory Officer',
    query: '"Katie Schmidt" "Fidelity National" OR "FNF" email contact OR speaker OR conference OR interview' },
  { industry: 'title_escrow', role: 'title_closer', tier: 'primary', title: 'Brian Maughan — FNF Chief Marketing & Innovation Officer',
    query: '"Brian Maughan" "Fidelity National" OR "FNF" email contact OR speaker OR conference OR interview' },
  { industry: 'title_escrow', role: 'title_closer', tier: 'primary', title: 'Elizabeth Reilly — FNF Chief Privacy Officer',
    query: '"Elizabeth Reilly" "Fidelity National" OR "FNF" email contact OR speaker OR conference OR interview' },
  { industry: 'title_escrow', role: 'title_closer', tier: 'primary', title: 'Mike Nolan — FNF CEO',
    query: '"Mike Nolan" "Fidelity National" OR "FNF" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'title_escrow', role: 'title_closer', tier: 'primary', title: 'Leadership emails — FNF Investor page',
    query: 'site:investor.fnf.com "leadership" OR "executive" email contact' },

  // ════════════════════════════════════════════════════════
  // TITLE INSURANCE — Old Republic Title (named contacts)
  // ════════════════════════════════════════════════════════
  { industry: 'title_escrow', role: 'title_closer', tier: 'primary', title: 'Joe Aperfine — Old Republic Title CIO',
    query: '"Joe Aperfine" "Old Republic" email contact OR speaker OR conference OR interview' },
  { industry: 'title_escrow', role: 'title_closer', tier: 'primary', title: 'Mark Budzinski — Old Republic Chief Legal Officer',
    query: '"Mark Budzinski" "Old Republic" email contact OR speaker OR conference OR interview' },
  { industry: 'title_escrow', role: 'title_closer', tier: 'primary', title: 'Kent Lewis — Old Republic EVP General Counsel',
    query: '"Kent Lewis" "Old Republic" email contact OR speaker OR conference OR interview' },
  { industry: 'title_escrow', role: 'title_closer', tier: 'primary', title: 'Rob Zellar — Old Republic Chief Strategy Officer',
    query: '"Rob Zellar" "Old Republic" email contact OR speaker OR conference OR interview' },
  { industry: 'title_escrow', role: 'title_closer', tier: 'primary', title: 'Carolyn Monroe — Old Republic CEO',
    query: '"Carolyn Monroe" "Old Republic" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'title_escrow', role: 'title_closer', tier: 'primary', title: 'Bill Robinson — Old Republic EVP Enterprise Services',
    query: '"Bill Robinson" "Old Republic" email contact OR speaker OR conference OR interview' },
  { industry: 'title_escrow', role: 'title_closer', tier: 'primary', title: 'Leadership emails — Old Republic Title',
    query: 'site:oldrepublictitle.com "leadership" email contact' },

  // ════════════════════════════════════════════════════════
  // TITLE / REAL ESTATE — Anywhere Real Estate, Compass
  // ════════════════════════════════════════════════════════
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'SVP Transaction Services — Anywhere Real Estate',
    query: '"Anywhere Real Estate" "SVP Transaction Services" OR "Transaction Services" director email contact site:linkedin.com OR site:anywhere.re' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'VP Compliance — Compass',
    query: '"Compass" real estate "VP Compliance" OR "Chief Compliance Officer" email contact site:linkedin.com OR site:compass.com' },

  // ════════════════════════════════════════════════════════
  // MORTGAGE & LENDING — named + role-based
  // ════════════════════════════════════════════════════════
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Nicole Beattie — Amrock CEO',
    query: '"Nicole Beattie" "Amrock" OR "Rocket" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Shawn Malhotra — Rocket Mortgage CTO',
    query: '"Shawn Malhotra" "Rocket" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Jay Jones — Rocket Chief Servicing Officer',
    query: '"Jay Jones" "Rocket" email contact OR speaker OR conference OR interview' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Heather Lovier — Amrock COO',
    query: '"Heather Lovier" "Amrock" email contact OR speaker OR conference OR interview' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Chief Risk Officer — Mr. Cooper',
    query: '"Mr. Cooper" "Chief Risk Officer" OR "VP Enterprise Records" email contact site:linkedin.com OR site:mrcooper.com' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Chief Compliance Officer — loanDepot',
    query: '"loanDepot" "Chief Compliance Officer" OR "VP Loan Operations" email contact site:linkedin.com OR site:loandepot.com' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Director Document Governance — Freedom Mortgage',
    query: '"Freedom Mortgage" "Document Governance" OR "Chief Compliance" director email contact site:linkedin.com' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'VP Digital Transformation — UWM',
    query: '"UWM" OR "United Wholesale Mortgage" "VP Digital" OR "Digital Transformation" director email contact site:linkedin.com' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Head of Enterprise Records — Newrez',
    query: '"Newrez" "Enterprise Records" OR "Chief Compliance" OR "VP Operations" director email contact site:linkedin.com' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Chief Compliance Officer — Pennymac',
    query: '"Pennymac" "Chief Compliance Officer" OR "VP Loan Operations" email contact site:linkedin.com OR site:pennymac.com' },

  // ════════════════════════════════════════════════════════
  // COMMERCIAL REAL ESTATE — Cushman & Wakefield, Colliers, Newmark
  // ════════════════════════════════════════════════════════
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'CIO — Cushman & Wakefield',
    query: '"Cushman Wakefield" "Chief Information Officer" OR "Director Information Governance" email contact site:linkedin.com OR site:cushmanwakefield.com' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Head Digital Transformation — Colliers',
    query: '"Colliers" "Head of Digital Transformation" OR "Chief Digital Officer" email contact site:linkedin.com OR site:colliers.com' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Chief Risk Officer — Newmark',
    query: '"Newmark" "Chief Risk Officer" OR "Head of Risk" email contact site:linkedin.com OR site:nmrk.com' },

  // ════════════════════════════════════════════════════════
  // TIER 4: GLOBAL BANKS
  // ════════════════════════════════════════════════════════
  { industry: 'banking', role: 'recorder', tier: 'primary', title: 'MD Digital Assets — JPMorgan Chase',
    query: '"JPMorgan" "Managing Director" "Digital Assets" OR "Document Intelligence" email contact site:linkedin.com OR site:jpmorganchase.com' },
  { industry: 'banking', role: 'recorder', tier: 'primary', title: 'Chief Data Officer — Bank of America',
    query: '"Bank of America" "Chief Data Officer" OR "Head of Mortgage Technology" email contact site:linkedin.com OR site:bankofamerica.com' },
  { industry: 'banking', role: 'recorder', tier: 'primary', title: 'VP Enterprise Records — Wells Fargo',
    query: '"Wells Fargo" "VP Enterprise Records" OR "Head of Document Management" email contact site:linkedin.com OR site:wellsfargo.com' },
  { industry: 'banking', role: 'recorder', tier: 'primary', title: 'Head of Operational Risk — Citigroup',
    query: '"Citigroup" OR "Citi" "Head of Operational Risk" OR "Document Governance" director email contact site:linkedin.com' },
  { industry: 'banking', role: 'recorder', tier: 'primary', title: 'Head Financial Crime Technology — HSBC',
    query: '"HSBC" "Head of Financial Crime Technology" OR "Financial Crime" director email contact site:linkedin.com OR site:hsbc.com' },
  { industry: 'banking', role: 'recorder', tier: 'primary', title: 'Head of Digital Trust — Standard Chartered',
    query: '"Standard Chartered" "Head of Digital Trust" OR "Digital Compliance" director email contact site:linkedin.com OR site:sc.com' },

  // ════════════════════════════════════════════════════════
  // TIER 5: LEGAL — additional firms (Dentons)
  // ════════════════════════════════════════════════════════
  { industry: 'global_legal', role: 'global_law_firm', tier: 'primary', title: 'Head Knowledge Management — Dentons',
    query: '"Dentons" "Head of Knowledge Management" OR "Chief Innovation Officer" OR "Legal Technology" director email contact site:linkedin.com OR site:dentons.com' },

  // ════════════════════════════════════════════════════════
  // TIER 6: LAND REGISTRIES (named searches)
  // ════════════════════════════════════════════════════════
  { industry: 'gov_regulator', role: 'gov_regulator', tier: 'primary', title: 'Head Digital Transformation — HM Land Registry',
    query: 'site:gov.uk "HM Land Registry" "Head of Digital" OR "Digital Transformation" OR "CTO" email contact staff' },
  { industry: 'gov_regulator', role: 'gov_regulator', tier: 'primary', title: 'Director Innovation — Dubai Land Department',
    query: '"Dubai Land Department" "Director" "Innovation" OR "Digital" OR "Technology" email contact site:linkedin.com OR site:dubailand.gov.ae' },
  { industry: 'gov_regulator', role: 'gov_regulator', tier: 'primary', title: 'CTO — Singapore Land Authority',
    query: 'site:sla.gov.sg "Chief Technology Officer" OR "Director" "Digital" OR "Technology" email contact staff' },
  { industry: 'gov_regulator', role: 'gov_regulator', tier: 'primary', title: 'Head Digital Trust — NSW Land Registry',
    query: '"NSW Land Registry" OR "New South Wales Land Registry" "Head of Digital" OR "Director" email contact site:linkedin.com' },
  { industry: 'gov_regulator', role: 'gov_regulator', tier: 'primary', title: 'Director Records Integrity — Ontario Land Registry',
    query: '"Ontario Land Registry" "Director" "Records" OR "Digital" OR "Integrity" email contact site:ontario.ca OR site:linkedin.com' },
  { industry: 'gov_regulator', role: 'gov_regulator', tier: 'primary', title: 'County Recorder CIO — US County Offices',
    query: '"County Recorder" OR "Register of Deeds" "CIO" OR "Chief Information Officer" OR "Director Records" email contact site:linkedin.com' },

  // ════════════════════════════════════════════════════════
  // TIER 7: INSURANCE EXPANSION — Zurich (named), Munich Re, Swiss Re, Travelers, Liberty Mutual, Hartford, CNA, Nationwide
  // ════════════════════════════════════════════════════════
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Ian Thompson — Zurich Group Chief Claims Officer',
    query: '"Ian Thompson" "Zurich" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Annarita Roscino — Zurich Claims Analytics',
    query: '"Annarita Roscino" "Zurich" email contact OR speaker OR conference OR interview' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Andrew Fairclough — Zurich Claims Excellence',
    query: '"Andrew Fairclough" "Zurich" email contact OR speaker OR conference OR interview' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Delpha DiGiacomo — Zurich Head of Fraud',
    query: '"Delpha DiGiacomo" "Zurich" email contact OR speaker OR conference OR interview' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Raffaello Consigli — Zurich SIU',
    query: '"Raffaello Consigli" "Zurich" email contact OR speaker OR conference OR interview' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Aleksandar Vidovic — Zurich Fraud AI',
    query: '"Aleksandar Vidovic" "Zurich" email contact OR speaker OR conference OR interview' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Head Fraud Analytics — Munich Re',
    query: '"Munich Re" "Head of Fraud" OR "Fraud Analytics" OR "Claims Innovation" director email contact site:linkedin.com OR site:munichre.com' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Digital Claims Leader — Swiss Re',
    query: '"Swiss Re" "Digital Claims" OR "Claims Innovation" director email contact site:linkedin.com OR site:swissre.com' },
  // TRAVELERS — named contacts
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Nicholas Seminara — Travelers Chief Claim Officer',
    query: '"Nicholas Seminara" "Travelers" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Kevin Smith — Travelers Chief Innovation Officer',
    query: '"Kevin Smith" "Travelers" insurance email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Mojgan Lefebvre — Travelers CTOO',
    query: '"Mojgan Lefebvre" "Travelers" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Bruce Jones — Travelers Chief Risk Officer',
    query: '"Bruce Jones" "Travelers" insurance email contact OR speaker OR conference OR interview' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Avrohom Kess — Travelers Chief Legal Officer',
    query: '"Avrohom Kess" "Travelers" email contact OR speaker OR conference OR interview' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Gregory Toczydlowski — Travelers Business Insurance',
    query: '"Gregory Toczydlowski" "Travelers" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Erik Roen — Travelers CIO Claim Technology',
    query: '"Erik Roen" "Travelers" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Judy ONeill — Travelers VP Claims',
    query: '"Judy" "ONeill" OR "O\'Neill" "Travelers" email contact OR speaker OR conference OR interview' },

  // LIBERTY MUTUAL — named contacts
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Monica Caldas — Liberty Mutual EVP CIO',
    query: '"Monica Caldas" "Liberty Mutual" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Matthew Moore — Liberty Mutual President Underwriting',
    query: '"Matthew Moore" "Liberty Mutual" email contact OR speaker OR conference OR interview' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Susanne Figueredo Cook — Liberty Mutual COO',
    query: '"Susanne Figueredo" OR "Susanne Cook" "Liberty Mutual" email contact OR speaker OR conference OR interview' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Neeti Bhalla Johnson — Liberty Mutual Global Risk',
    query: '"Neeti Bhalla Johnson" "Liberty Mutual" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Tim Sweeney — Liberty Mutual CEO',
    query: '"Tim Sweeney" "Liberty Mutual" email contact OR speaker OR conference OR interview OR podcast' },

  // MUNICH RE — named contacts
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Declan ONeill — Munich Re Head Digital Innovation',
    query: '"Declan" "ONeill" OR "O\'Neill" "Munich Re" email contact OR speaker OR conference OR interview' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Patrick Sullivan — Munich Re SVP Integrated Analytics',
    query: '"Patrick Sullivan" "Munich Re" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Tobias Frenz — Munich Re Digital Solutions APAC',
    query: '"Tobias Frenz" "Munich Re" email contact OR speaker OR conference OR interview' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Sven Erichsen — Munich Re Markets Digital',
    query: '"Sven Erichsen" "Munich Re" email contact OR speaker OR conference OR interview' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Ross Mayne — Munich Re CEO Automation Solutions',
    query: '"Ross Mayne" "Munich Re" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Bilal Ramadan — Munich Re CEO HealthTech',
    query: '"Bilal Ramadan" "Munich Re" email contact OR speaker OR conference OR interview' },

  // SWISS RE — named contacts
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Pravina Ladva — Swiss Re Group CDTO',
    query: '"Pravina Ladva" "Swiss Re" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Bernhard Kaufmann — Swiss Re Group CRO',
    query: '"Bernhard Kaufmann" "Swiss Re" email contact OR speaker OR conference OR interview' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Hermann Geiger — Swiss Re Group Legal',
    query: '"Hermann Geiger" "Swiss Re" email contact OR speaker OR conference OR interview' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Henock Teklu — Swiss Re Transformation',
    query: '"Henock Teklu" "Swiss Re" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Marc Scheidegger — Swiss Re Chief Claims Officer',
    query: '"Marc Scheidegger" "Swiss Re" email contact OR speaker OR conference OR interview' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Annette Kurtzweil — Swiss Re CRO Corporate Solutions',
    query: '"Annette Kurtzweil" "Swiss Re" email contact OR speaker OR conference OR interview' },

  // THE HARTFORD — named contacts
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Steve Deane — Hartford Chief Claims Officer',
    query: '"Steve Deane" "Hartford" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Prateek Chhabra — Hartford Chief Risk Officer',
    query: '"Prateek Chhabra" "Hartford" email contact OR speaker OR conference OR interview' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Jeffery Hawkins — Hartford Chief Data AI Officer',
    query: '"Jeffery Hawkins" "Hartford" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Shekar Pannala — Hartford CIO',
    query: '"Shekar Pannala" "Hartford" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Don Hunt — Hartford General Counsel',
    query: '"Don Hunt" "Hartford" insurance email contact OR speaker OR conference OR interview' },

  // SWISS RE, CNA, HARTFORD — role-based fallbacks
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Global Head Claims Transformation — Swiss Re',
    query: '"Swiss Re" "Global Head" "Claims Transformation" OR "Digital Risk" OR "Chief Data Officer" OR "Fraud Analytics" email contact site:linkedin.com OR site:swissre.com' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Chief Claims Officer — CNA Financial',
    query: '"CNA Financial" "Chief Claims Officer" OR "Head of Claims Innovation" OR "VP SIU" OR "Document Governance" email contact site:linkedin.com OR site:cna.com' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Head Claims Transformation — The Hartford',
    query: '"The Hartford" "Head of Claims Transformation" OR "VP Fraud Analytics" OR "Chief Digital Officer" email contact site:linkedin.com OR site:thehartford.com' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'VP Digital Claims — Nationwide',
    query: '"Nationwide" insurance "VP Digital Claims" OR "Claims Innovation" director email contact site:linkedin.com OR site:nationwide.com' },

  // CUSHMAN & WAKEFIELD — named contacts
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Sal Companieh — Cushman Chief Digital & Information Officer',
    query: '"Sal Companieh" "Cushman" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Payman Sadegh — Cushman Chief Data Officer',
    query: '"Payman Sadegh" "Cushman" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Noelle Perkins — Cushman Chief Legal Officer',
    query: '"Noelle Perkins" "Cushman" email contact OR speaker OR conference OR interview' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Nathaniel Robinson — Cushman Chief Strategy Officer',
    query: '"Nathaniel Robinson" "Cushman Wakefield" email contact OR speaker OR conference OR interview' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Leadership page scrape — Cushman & Wakefield',
    query: 'site:cushmanwakefield.com "leadership" email contact' },

  // COLLIERS — named contacts
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Stuart McDonald — Colliers Global CIO',
    query: '"Stuart McDonald" "Colliers" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Matthew Hawkins — Colliers SVP Legal',
    query: '"Matthew Hawkins" "Colliers" email contact OR speaker OR conference OR interview' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Jay Hennick — Colliers CEO',
    query: '"Jay Hennick" "Colliers" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Christian Mayer — Colliers COO',
    query: '"Christian Mayer" "Colliers" email contact OR speaker OR conference OR interview' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Leadership page scrape — Colliers',
    query: 'site:corporate.colliers.com "leadership" email contact' },

  // NEWMARK — named role scrapes
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'CIO / CTO — Newmark',
    query: 'site:nmrk.com "Chief Information Officer" OR "Chief Technology Officer" OR "Chief Digital Officer" email contact leadership' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'General Counsel / Head Operations Tech — Newmark',
    query: '"Newmark" "General Counsel" OR "Head of Operations Technology" OR "Compliance Director" email contact site:linkedin.com' },

  // JPMORGAN — mortgage/real estate/compliance named role scrapes
  { industry: 'banking', role: 'recorder', tier: 'primary', title: 'Head Mortgage Technology — JPMorgan Chase',
    query: '"JPMorgan" OR "Chase" "Head of Mortgage Technology" OR "Head of Collateral Management" OR "Document Intelligence" director email contact site:linkedin.com' },
  { industry: 'banking', role: 'recorder', tier: 'primary', title: 'MD Digital Assets — JPMorgan Chase leadership page',
    query: 'site:jpmorganchase.com "Managing Director" "Digital" OR "Document" OR "Collateral" email contact leadership' },

  // WELLS FARGO — home lending / enterprise records
  { industry: 'banking', role: 'recorder', tier: 'primary', title: 'Head Home Lending Technology — Wells Fargo',
    query: '"Wells Fargo" "Head of Home Lending Technology" OR "Head of Mortgage Operations" OR "Enterprise Records" email contact site:linkedin.com' },
  { industry: 'banking', role: 'recorder', tier: 'primary', title: 'Head Financial Crimes Technology — Wells Fargo',
    query: '"Wells Fargo" "Head of Financial Crimes Technology" OR "Chief Compliance Officer" director email contact site:linkedin.com OR site:wellsfargo.com' },

  // ════════════════════════════════════════════════════════
  // CLINICALTRIALS.GOV — real PI/contact emails via direct API
  // source:'clinicaltrials' routes to searchLeadsViaClinicalTrials()
  // ════════════════════════════════════════════════════════
  { industry: 'pharma', role: 'pharma_cco', tier: 'primary', source: 'clinicaltrials', sponsor: 'Pfizer',                      company: 'Pfizer',                      title: 'Clinical PI — Pfizer' },
  { industry: 'pharma', role: 'pharma_cco', tier: 'primary', source: 'clinicaltrials', sponsor: 'Johnson & Johnson',            company: 'Johnson & Johnson',            title: 'Clinical PI — J&J' },
  { industry: 'pharma', role: 'pharma_cco', tier: 'primary', source: 'clinicaltrials', sponsor: 'Novartis',                     company: 'Novartis',                     title: 'Clinical PI — Novartis' },
  { industry: 'pharma', role: 'pharma_cco', tier: 'primary', source: 'clinicaltrials', sponsor: 'Roche',                        company: 'Roche',                        title: 'Clinical PI — Roche' },
  { industry: 'pharma', role: 'pharma_cco', tier: 'primary', source: 'clinicaltrials', sponsor: 'Merck',                        company: 'Merck',                        title: 'Clinical PI — Merck' },
  { industry: 'pharma', role: 'pharma_cco', tier: 'primary', source: 'clinicaltrials', sponsor: 'AstraZeneca',                  company: 'AstraZeneca',                  title: 'Clinical PI — AstraZeneca' },
  { industry: 'pharma', role: 'pharma_cco', tier: 'primary', source: 'clinicaltrials', sponsor: 'GlaxoSmithKline',              company: 'GSK',                          title: 'Clinical PI — GSK' },
  { industry: 'pharma', role: 'pharma_cco', tier: 'primary', source: 'clinicaltrials', sponsor: 'Bayer',                        company: 'Bayer',                        title: 'Clinical PI — Bayer' },
  { industry: 'pharma', role: 'pharma_cco', tier: 'primary', source: 'clinicaltrials', sponsor: 'AbbVie',                       company: 'AbbVie',                       title: 'Clinical PI — AbbVie' },
  { industry: 'pharma', role: 'pharma_cco', tier: 'primary', source: 'clinicaltrials', sponsor: 'Eli Lilly',                    company: 'Eli Lilly',                    title: 'Clinical PI — Eli Lilly' },
  { industry: 'pharma', role: 'pharma_cco', tier: 'primary', source: 'clinicaltrials', sponsor: 'Bristol-Myers Squibb',         company: 'Bristol-Myers Squibb',         title: 'Clinical PI — BMS' },
  { industry: 'pharma', role: 'pharma_cco', tier: 'primary', source: 'clinicaltrials', sponsor: 'Sanofi',                       company: 'Sanofi',                       title: 'Clinical PI — Sanofi' },
  { industry: 'pharma', role: 'pharma_cco', tier: 'primary', source: 'clinicaltrials', sponsor: 'Moderna',                      company: 'Moderna',                      title: 'Clinical PI — Moderna' },
  { industry: 'pharma', role: 'pharma_cco', tier: 'primary', source: 'clinicaltrials', sponsor: 'Amgen',                        company: 'Amgen',                        title: 'Clinical PI — Amgen' },
  { industry: 'pharma', role: 'pharma_cco', tier: 'primary', source: 'clinicaltrials', sponsor: 'Gilead Sciences',              company: 'Gilead Sciences',              title: 'Clinical PI — Gilead' },
  { industry: 'healthcare', role: 'healthcare', tier: 'primary', source: 'clinicaltrials', sponsor: 'Mayo Clinic',              company: 'Mayo Clinic',                  title: 'Clinical PI — Mayo Clinic' },
  { industry: 'healthcare', role: 'healthcare', tier: 'primary', source: 'clinicaltrials', sponsor: 'Cleveland Clinic',         company: 'Cleveland Clinic',             title: 'Clinical PI — Cleveland Clinic' },
  { industry: 'healthcare', role: 'healthcare', tier: 'primary', source: 'clinicaltrials', sponsor: 'Johns Hopkins',            company: 'Johns Hopkins',                title: 'Clinical PI — Johns Hopkins' },
  { industry: 'healthcare', role: 'healthcare', tier: 'primary', source: 'clinicaltrials', sponsor: 'Massachusetts General Hospital', company: 'Mass General Hospital',   title: 'Clinical PI — Mass General' },

  // ════════════════════════════════════════════════════════
  // PUBMED — corresponding author emails in research papers
  // source:'pubmed' routes to searchLeadsViaPubMed()
  // ════════════════════════════════════════════════════════
  { industry: 'university_research', role: 'university_research', tier: 'primary', source: 'pubmed', company: 'Harvard University',  title: 'Research Author — Harvard',   pubmedQuery: 'Harvard[Affiliation] "data integrity" OR "research compliance" AND hasabstract[text]' },
  { industry: 'university_research', role: 'university_research', tier: 'primary', source: 'pubmed', company: 'MIT',                 title: 'Research Author — MIT',       pubmedQuery: 'Massachusetts Institute of Technology[Affiliation] "data integrity" OR "reproducibility" AND hasabstract[text]' },
  { industry: 'university_research', role: 'university_research', tier: 'primary', source: 'pubmed', company: 'Stanford University', title: 'Research Author — Stanford',  pubmedQuery: 'Stanford[Affiliation] "research compliance" OR "data integrity" AND hasabstract[text]' },
  { industry: 'university_research', role: 'university_research', tier: 'primary', source: 'pubmed', company: 'Oxford University',   title: 'Research Author — Oxford',    pubmedQuery: 'Oxford[Affiliation] "research integrity" OR "data fabrication" AND hasabstract[text]' },
  { industry: 'university_research', role: 'university_research', tier: 'primary', source: 'pubmed', company: 'Cambridge University',title: 'Research Author — Cambridge', pubmedQuery: 'Cambridge[Affiliation] "research integrity" OR "data compliance" AND hasabstract[text]' },
  { industry: 'university_research', role: 'university_research', tier: 'primary', source: 'pubmed', company: 'University of Toronto', title: 'Research Author — U Toronto', pubmedQuery: 'Toronto[Affiliation] "research ethics" OR "data integrity" AND hasabstract[text]' },
  { industry: 'university_research', role: 'university_research', tier: 'primary', source: 'pubmed', company: 'ETH Zurich',          title: 'Research Author — ETH Zurich', pubmedQuery: 'ETH Zurich[Affiliation] "research integrity" OR "data compliance" AND hasabstract[text]' },
  { industry: 'pharma', role: 'pharma_cco', tier: 'primary', source: 'pubmed', company: 'Pfizer',      title: 'Research Author — Pfizer',   pubmedQuery: 'Pfizer[Affiliation] "clinical data" OR "regulatory compliance" AND hasabstract[text]' },
  { industry: 'pharma', role: 'pharma_cco', tier: 'primary', source: 'pubmed', company: 'Novartis',    title: 'Research Author — Novartis', pubmedQuery: 'Novartis[Affiliation] "clinical data" OR "data integrity" AND hasabstract[text]' },

  // ════════════════════════════════════════════════════════
  // MARTINDALE — attorney emails via site:martindale.com Serper queries
  // These use the standard Google search path
  // ════════════════════════════════════════════════════════
  { industry: 'global_legal', role: 'global_law_firm', tier: 'primary', title: 'Attorney — Kirkland Ellis eDiscovery',    query: 'site:martindale.com "Kirkland" "litigation" OR "eDiscovery" email' },
  { industry: 'global_legal', role: 'global_law_firm', tier: 'primary', title: 'Attorney — Latham Watkins eDiscovery',   query: 'site:martindale.com "Latham" "litigation support" OR "eDiscovery" email' },
  { industry: 'global_legal', role: 'global_law_firm', tier: 'primary', title: 'Attorney — Baker McKenzie eDiscovery',   query: 'site:martindale.com "Baker McKenzie" "litigation" OR "eDiscovery" email' },
  { industry: 'global_legal', role: 'global_law_firm', tier: 'primary', title: 'Attorney — DLA Piper litigation',        query: 'site:martindale.com "DLA Piper" "litigation" OR "legal technology" email' },
  { industry: 'global_legal', role: 'global_law_firm', tier: 'primary', title: 'Attorney — Skadden litigation',          query: 'site:martindale.com "Skadden" "litigation" OR "eDiscovery" email' },
  { industry: 'global_legal', role: 'global_law_firm', tier: 'primary', title: 'Attorney — Jones Day litigation',        query: 'site:martindale.com "Jones Day" "litigation" OR "legal technology" email' },
  { industry: 'global_legal', role: 'global_law_firm', tier: 'primary', title: 'Attorney — White Case litigation',       query: 'site:martindale.com "White Case" "litigation" OR "eDiscovery" email' },
  { industry: 'global_legal', role: 'global_law_firm', tier: 'primary', title: 'Attorney — Gibson Dunn litigation',      query: 'site:martindale.com "Gibson Dunn" "litigation" OR "legal technology" email' },
  { industry: 'global_legal', role: 'global_law_firm', tier: 'primary', title: 'Attorney — Norton Rose litigation',      query: 'site:martindale.com "Norton Rose" "litigation" OR "eDiscovery" email' },
  { industry: 'global_legal', role: 'global_law_firm', tier: 'primary', title: 'Attorney — Sidley Austin litigation',    query: 'site:martindale.com "Sidley" "litigation" OR "legal technology" email' },

  // ════════════════════════════════════════════════════════
  // INSURANCE — Director-level Claims Transformation, Fraud Analytics, Operations
  // These are one level below C-suite but have direct budget/pilot authority
  // ════════════════════════════════════════════════════════
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Director Claims Transformation — Chubb',
    query: '"Chubb" "Director" "Claims Transformation" OR "Claims Innovation" OR "Claims Modernization" email contact site:linkedin.com OR conference OR speaker' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Fraud Analytics Director — Chubb',
    query: '"Chubb" "Fraud Analytics" OR "SIU Director" OR "Special Investigations" OR "Fraud Detection" director email contact site:linkedin.com' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Claims Operations Director — Chubb',
    query: '"Chubb" "Claims Operations" OR "VP Claims Operations" OR "Director Claims Operations" email contact site:linkedin.com OR site:chubb.com' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Director Claims Transformation — AIG',
    query: '"AIG" "Director" "Claims Transformation" OR "Claims Innovation" OR "Claims Technology" email contact site:linkedin.com OR conference OR speaker' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Fraud Analytics Director — AIG',
    query: '"AIG" "Fraud Analytics" OR "SIU Director" OR "Special Investigations" OR "Fraud Detection" director email contact site:linkedin.com' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Director Claims Transformation — Travelers',
    query: '"Travelers" "Director" "Claims Transformation" OR "Claims Innovation" OR "Digital Claims" email contact site:linkedin.com OR conference OR speaker' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Fraud Analytics Director — Travelers',
    query: '"Travelers Insurance" "Fraud Analytics" OR "SIU" OR "Special Investigations Director" email contact site:linkedin.com' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Director Claims Transformation — Zurich',
    query: '"Zurich Insurance" "Director" "Claims Transformation" OR "Claims Innovation" OR "Digital Claims" email contact site:linkedin.com OR site:zurich.com' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Fraud Analytics Director — Zurich',
    query: '"Zurich" "Fraud Analytics" OR "SIU" OR "Special Investigations" OR "Fraud Detection" director email contact site:linkedin.com' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Director Claims Transformation — Hartford',
    query: '"The Hartford" "Director" "Claims Transformation" OR "Claims Innovation" OR "Digital Claims" email contact site:linkedin.com' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Fraud Analytics Director — Liberty Mutual',
    query: '"Liberty Mutual" "Fraud Analytics" OR "SIU Director" OR "Special Investigations" director email contact site:linkedin.com' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Digital Claims Manager — Allianz',
    query: '"Allianz" "Digital Claims" OR "Claims Automation" OR "Claims Innovation" manager director email contact site:linkedin.com OR site:allianz.com OR site:allianz.co.uk' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Claims Operations Director — Allianz',
    query: '"Allianz" "Claims Operations" OR "Head of Claims Operations" OR "Director Claims" email contact site:linkedin.com OR site:allianz.co.uk' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Chief Claims Transformation Officer — AXA UK',
    query: '"AXA" "Claims Transformation" OR "Digital Claims" OR "Chief Claims" director email contact site:linkedin.com OR site:axa.co.uk' },

  // ════════════════════════════════════════════════════════
  // CRE — Director-level Information Governance, Transaction Tech, Property Tech
  // Below CIO level; these people run pilots and own document workflows
  // ════════════════════════════════════════════════════════
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Head Information Governance — CBRE',
    query: '"CBRE" "Information Governance" OR "Records Management" OR "Data Governance" head director email contact site:linkedin.com' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Director Transaction Technology — CBRE',
    query: '"CBRE" "Transaction Technology" OR "Transact Platform" OR "Lease Administration Technology" director email contact site:linkedin.com' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Head Property Technology — CBRE',
    query: '"CBRE" "Property Technology" OR "PropTech" OR "Enterprise Applications" head director email contact site:linkedin.com' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Director Lease Administration — CBRE',
    query: '"CBRE" "Lease Administration" OR "AI-enabled lease" OR "Lease Technology" director head email contact site:linkedin.com' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Head Information Governance — JLL',
    query: '"JLL" "Information Governance" OR "Data Governance" OR "Records Management" head director email contact site:linkedin.com' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Director Transaction Technology — JLL',
    query: '"JLL" "Transaction Management Technology" OR "Workplace Technology" OR "Lease Administration" director email contact site:linkedin.com' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Head Property Technology — JLL',
    query: '"JLL" "Property Technology" OR "PropTech" OR "Digital Product" head director email contact site:linkedin.com' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Head Information Governance — Cushman Wakefield',
    query: '"Cushman Wakefield" "Information Governance" OR "Data Governance" OR "Enterprise Data" head director email contact site:linkedin.com' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Director Occupier Experience Technology — Cushman',
    query: '"Cushman Wakefield" "Occupier Experience Technology" OR "Occupier Technology" OR "Property Technology" director email contact site:linkedin.com' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Director Transaction Technology — Cushman',
    query: '"Cushman Wakefield" "Transaction Technology" OR "Lease Administration Technology" OR "Enterprise Applications" director email contact site:linkedin.com' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Head Information Governance — Colliers',
    query: '"Colliers" "Information Governance" OR "Data Governance" OR "Records Management" head director email contact site:linkedin.com' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Head Property Technology — Colliers',
    query: '"Colliers" "Property Technology" OR "PropTech" OR "Digital Workplace" head director email contact site:linkedin.com' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Head Information Governance — Newmark',
    query: '"Newmark" "Information Governance" OR "Data Governance" OR "Enterprise Applications" head director email contact site:linkedin.com OR site:nmrk.com' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Director Transaction Technology — Newmark',
    query: '"Newmark" "Transaction Technology" OR "Lease Administration" OR "GCS Technology" director email contact site:linkedin.com' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Director Digital Transformation — Newmark',
    query: '"Newmark" "Digital Transformation" OR "Enterprise Technology" OR "Head of Technology" director email contact site:linkedin.com OR site:nmrk.com' },

  // ════════════════════════════════════════════════════════
  // NAMED — Batch 6 people (imported but need email-hunt LEAD_TARGETS)
  // ════════════════════════════════════════════════════════
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Margaret Scott — Allianz Director Claims Strategy',
    query: '"Margaret Scott" "Allianz" email contact OR speaker OR conference OR interview' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Lee Watts — Allianz Director Technical Claims',
    query: '"Lee Watts" "Allianz" email contact OR speaker OR conference OR interview' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Shelley Hughes — Allianz Digital Claims Propositions',
    query: '"Shelley Hughes" "Allianz" email contact OR speaker OR conference OR interview' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Graham Stait — Allianz Head Claims Operations',
    query: '"Graham Stait" "Allianz" email contact OR speaker OR conference OR interview' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Martin Milliner — AXA Chief Claims Transformation Officer',
    query: '"Martin Milliner" "AXA" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Jo Ann Rabitz — Chubb Operations Leadership',
    query: '"Jo Ann Rabitz" OR "JoAnn Rabitz" "Chubb" email contact OR speaker OR conference OR interview' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Kathleen Stubbs — Colliers Regional IT Director APAC',
    query: '"Kathleen Stubbs" "Colliers" email contact OR speaker OR conference OR interview' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Ferial Sheybani — Colliers VP Technology & Data',
    query: '"Ferial Sheybani" "Colliers" email contact OR speaker OR conference OR interview' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Christian Reitz — Colliers CTO',
    query: '"Christian Reitz" "Colliers" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Sridhar Potineni — Newmark CIO',
    query: '"Sridhar Potineni" "Newmark" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Garrett Cannon — Newmark Co-Head Information & Technology',
    query: '"Garrett Cannon" "Newmark" email contact OR speaker OR conference OR interview' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Carla Hinson — Newmark Technology Executive',
    query: '"Carla Hinson" "Newmark" email contact OR speaker OR conference OR interview' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Kapil Lahoti — CBRE EVP Digital & Technology Advisory',
    query: '"Kapil Lahoti" "CBRE" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Denis McGowan — CBRE Global Workplace Solutions',
    query: '"Denis McGowan" "CBRE" email contact OR speaker OR conference OR interview' },
  { industry: 'real_estate', role: 'real_estate_ops', tier: 'primary', title: 'Vinay Goel — JLL Chief Digital Product Officer',
    query: '"Vinay Goel" "JLL" email contact OR speaker OR conference OR interview OR podcast' },
  { industry: 'global_insurance', role: 'global_insurance', tier: 'primary', title: 'Nelcia Oliveira — Zurich Regional Chief Claims Officer',
    query: '"Nelcia Oliveira" "Zurich" email contact OR speaker OR conference OR interview' },
];

// ─────────────────────────────────────────────────────────────────────────────
// AFFILIATE TARGETS — partner recruitment across 5 segments
// ─────────────────────────────────────────────────────────────────────────────
const AFFILIATE_TARGETS = [
  // 1. Safety Net — Insurance & Real Estate
  { industry: 'affiliate_insurance', role: 'aff_insurance', tier: 'affiliate', title: 'Independent Insurance Broker',   query: '"independent insurance broker" USA contact email site:linkedin.com OR site:*.com' },
  { industry: 'affiliate_insurance', role: 'aff_insurance', tier: 'affiliate', title: 'Real Estate Broker Owner',        query: '"real estate broker" owner independent brokerage USA contact email' },
  { industry: 'affiliate_insurance', role: 'aff_insurance', tier: 'affiliate', title: 'Property Manager',               query: '"property management company" owner director USA contact email' },
  { industry: 'affiliate_insurance', role: 'aff_insurance', tier: 'affiliate', title: 'Title Insurance Agent',          query: '"title insurance agent" independent USA contact email' },
  { industry: 'affiliate_insurance', role: 'aff_insurance', tier: 'affiliate', title: 'E&O Insurance Specialist',       query: '"errors and omissions insurance" broker specialist real estate USA contact email' },

  // 2. Low-Trust Marketplaces
  { industry: 'affiliate_marketplace', role: 'aff_marketplace', tier: 'affiliate', title: 'Domain Marketplace Founder',    query: '"domain broker" OR "domain marketplace" founder owner USA contact email' },
  { industry: 'affiliate_marketplace', role: 'aff_marketplace', tier: 'affiliate', title: 'Collectibles Platform Owner',   query: '"collectibles marketplace" OR "high-end collectibles" platform owner founder USA contact email' },
  { industry: 'affiliate_marketplace', role: 'aff_marketplace', tier: 'affiliate', title: 'Freelance Platform Founder',    query: '"freelance marketplace" founder CEO USA contact email' },
  { industry: 'affiliate_marketplace', role: 'aff_marketplace', tier: 'affiliate', title: 'NFT/Digital Asset Platform CEO',query: '"digital asset" OR "NFT marketplace" CEO founder USA contact email' },
  { industry: 'affiliate_marketplace', role: 'aff_marketplace', tier: 'affiliate', title: 'Business Broker',              query: '"business broker" independent USA contact email site:bizbuysell.com OR site:*.com' },

  // 3. Legal Tech Content
  { industry: 'affiliate_legaltech', role: 'aff_legaltech', tier: 'affiliate', title: 'Legal Blogger / Attorney Author',  query: '"legal blog" attorney author OR founder USA contact email' },
  { industry: 'affiliate_legaltech', role: 'aff_legaltech', tier: 'affiliate', title: 'Notary Public Influencer',         query: '"notary public" youtube OR podcast OR blog creator USA contact email' },
  { industry: 'affiliate_legaltech', role: 'aff_legaltech', tier: 'affiliate', title: 'LegalTech YouTuber',              query: 'legaltech youtube creator attorney USA contact email' },
  { industry: 'affiliate_legaltech', role: 'aff_legaltech', tier: 'affiliate', title: 'Paralegal Educator',              query: '"paralegal" educator trainer online course USA contact email' },
  { industry: 'affiliate_legaltech', role: 'aff_legaltech', tier: 'affiliate', title: 'Bar Association Newsletter Editor',query: '"bar association" newsletter editor OR communications director USA contact email' },

  // 4. B2B SaaS Bundling
  { industry: 'affiliate_saas', role: 'aff_saas', tier: 'affiliate', title: 'Proposal Software Founder',        query: '"proposal software" founder CEO USA contact email site:proposify.com OR site:*.com' },
  { industry: 'affiliate_saas', role: 'aff_saas', tier: 'affiliate', title: 'Contract Management SaaS CEO',     query: '"contract management" software CEO founder USA contact email' },
  { industry: 'affiliate_saas', role: 'aff_saas', tier: 'affiliate', title: 'HR Onboarding Platform Founder',   query: '"HR onboarding" software platform founder CEO USA contact email' },
  { industry: 'affiliate_saas', role: 'aff_saas', tier: 'affiliate', title: 'eSignature Tool Founder',          query: '"esignature" OR "e-signature" software founder CEO USA contact email' },
  { industry: 'affiliate_saas', role: 'aff_saas', tier: 'affiliate', title: 'Document Automation CEO',          query: '"document automation" software CEO founder USA contact email' },

  // 5. Legacy & Estate Planning
  { industry: 'affiliate_estate', role: 'aff_estate', tier: 'affiliate', title: 'Estate Planning Attorney',     query: '"estate planning attorney" independent USA contact email' },
  { industry: 'affiliate_estate', role: 'aff_estate', tier: 'affiliate', title: 'Wealth Manager / Advisor',     query: '"wealth manager" OR "wealth advisor" independent RIA USA contact email' },
  { industry: 'affiliate_estate', role: 'aff_estate', tier: 'affiliate', title: 'Funeral Director / Owner',     query: '"funeral home" owner director USA contact email' },
  { industry: 'affiliate_estate', role: 'aff_estate', tier: 'affiliate', title: 'Trust Officer',                query: '"trust officer" bank OR company USA contact email' },
  { industry: 'affiliate_estate', role: 'aff_estate', tier: 'affiliate', title: 'Succession Planning Consultant',query: '"succession planning" consultant advisor USA contact email' },
];

const AFFILIATE_EMAIL = (name, company, role) => {
  const first = name.split(' ')[0];

  if (role === 'aff_insurance') return `Hi ${first},

I work with independent brokers and agents who want to offer clients something that actually differentiates them — not another rate comparison, but real document protection.

ProofDeed uses blockchain to create tamper-proof, timestamped proof of any document — deeds, closing disclosures, inspection reports. When a client questions what was signed or when, there's an immutable record.

I'm looking for a small group of agents and brokers to join our affiliate program. You'd get a co-branded landing page, a referral commission on every client who signs up, and a simple way to position yourself as the agent who protects clients after closing.

Would a quick call make sense? I can walk you through the commission structure and the "Closing Gift" framing that's working well for other agents.

Scott Kiersten
Founder, ProofDeed
proofdeed.com`;

  if (role === 'aff_marketplace') return `Hi ${first},

Fraud and disputes are an operational cost for every marketplace. ProofDeed solves the verification problem — sellers can certify any document (provenance, authenticity, title) on the blockchain, and buyers see a "Verified by ProofDeed" badge they can trust.

I'm offering marketplace owners a revenue share on every verification fee generated through their platform. You solve a trust problem for your sellers, reduce dispute volume, and earn a passive commission.

Would it be worth a 20-minute call to see if this fits ${company}?

Scott Kiersten
Founder, ProofDeed
proofdeed.com`;

  if (role === 'aff_legaltech') return `Hi ${first},

Your audience trusts your recommendations on tools that actually protect clients. ProofDeed is one of those — blockchain-certified document proof that holds up when documents are disputed, questioned, or need to prove their timeline.

I'd like to offer you a high-commission affiliate arrangement and a "Case Study Kit" — pre-written content showing real scenarios where timestamped proof made the difference. Something your audience can act on immediately.

Happy to send the kit and commission details if you're open to it.

Scott Kiersten
Founder, ProofDeed
proofdeed.com`;

  if (role === 'aff_saas') return `Hi ${first},

${company} helps users create and manage documents — ProofDeed closes the loop by certifying them on the blockchain the moment they're finalized. It's the missing "Secure this document" button at the end of your workflow.

I'm looking for integration partners. The model is simple: an affiliate widget or API integration, and you earn a revenue share on every certification your users run through ProofDeed.

Worth a quick call to explore if there's a fit?

Scott Kiersten
Founder, ProofDeed
proofdeed.com`;

  if (role === 'aff_estate') return `Hi ${first},

Estate and succession planning creates the documents that matter most — and the ones most often disputed years later. ProofDeed gives your clients a blockchain-verified record of every critical document: wills, trust amendments, deeds, asset transfers.

I'm building a referral network of estate professionals. You'd introduce ProofDeed to clients as part of your planning process and earn a commission on every account. We can co-brand a "Digital Legacy" page for your practice.

Would a brief call make sense to walk through the program?

Scott Kiersten
Founder, ProofDeed
proofdeed.com`;

  return `Hi ${first},

I'm Scott, founder of ProofDeed — blockchain document certification. I'd love to explore whether there's a fit for a referral partnership with ${company}.

Scott Kiersten
proofdeed.com`;
};

// ─────────────────────────────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────
// UAE EMAIL — Dubai Paperless Strategy 2026 + VARA compliance hook
// Used for UAE real estate developers and automotive conglomerates.
// Strategy: frame around Dubai's government mandate — compliance pressure
// is already there; ProofDeed is the implementation layer.
// ─────────────────────────────────────────────────────────────────────────────
const UAE_EMAIL = (name, company, role) => {
  const first = name.split(' ')[0];

  // Real estate developer — Digital Transformation / CDO / CTO / CIO / Innovation
  const uae_redev = `Hi ${first},

As the UAE accelerates toward its 2026 Paperless Government mandate, the risk sitting at the center of every major developer's operation is the same: digital property documents — title deeds, sale agreements, NOCs, handover certificates — are easy to duplicate, alter, and forge once they leave your system.

The Dubai Land Department is already issuing blockchain-backed title deeds. The gap is in the private developer workflow: the documents your team creates, transfers, and stores before they ever reach DLD.

ProofDeed provides a single API call that anchors each document field to the Polygon blockchain at the moment of creation — sale price, unit number, buyer name, execution date — so any downstream alteration is immediately detectable. No system replacement. Compatible with your existing DMS and CRM.

Relevant to ${company}'s current digital transformation priorities:
→ Aligns with Dubai Paperless Strategy 2026 and VARA's data integrity standards
→ Provides cryptographic proof of document origination for DLD submissions
→ Reduces title dispute resolution time from weeks to minutes

See it in 2 minutes: proofdeed.com/demo

Worth a quick call?

Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // Real estate — Operations / Sales / Asset Management / Handover
  const uae_reops = `Hi ${first},

Property handover disputes and title transfer delays cost UAE developers significant time and legal exposure — and the root cause is almost always the same: a document that can't be independently verified as unaltered.

With the UAE's 2026 Paperless Mandate requiring all government-adjacent transactions to be fully digital, the operational risk is only increasing. A digital document with no cryptographic proof of integrity is a liability.

ProofDeed provides field-level blockchain certification for every document in your handover and sales workflow — NOC, SPA, title deed, payment schedules — anchored at creation so ${company}'s team, your buyers, and the DLD all see the same verified original.

One API call. No workflow disruption. Works alongside your existing property management system.

See it in 2 minutes: proofdeed.com/demo

Worth 20 minutes?

Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // Real estate — Legal & Compliance
  const uae_legal = `Hi ${first},

VARA's expanding framework for virtual and digital assets in the UAE now requires demonstrable data integrity for any digital document used in regulated transactions. For a developer of ${company}'s scale, the exposure isn't just regulatory — it's the cost of a single contested title deed in arbitration.

ProofDeed provides immutable, cryptographic proof that every property document is unaltered from the moment of creation — sale price, buyer identity, execution timestamp, unit details — each field individually anchored to the blockchain. Independent third-party verifiability without relying on your internal system logs.

Relevant to your compliance posture:
→ Aligns with VARA data integrity standards
→ Supports DLD blockchain title deed ecosystem
→ Defensible audit trail for DIFC and ADGM arbitration

See it in 2 minutes: proofdeed.com/demo

Worth a conversation with your team?

Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // Real estate — Customer Experience / Post-Sales / CX
  const uae_recx = `Hi ${first},

The most common post-sale complaint at UAE property developers isn't price or quality — it's "that's not what my documents say." Buyers dispute handover conditions, payment schedules, and SPA terms because there's no cryptographic proof of what was agreed at signing.

ProofDeed anchors every customer-facing document — SPA, payment plan, handover certificate, NOC — to the blockchain at the moment it's issued. When a buyer questions a term, ${company}'s team can produce an independently verifiable proof in seconds, not weeks of email chains.

Reduces post-sale disputes. Builds buyer confidence. Aligns with Dubai's 2026 digital mandate.

See it in 2 minutes: proofdeed.com/demo

Worth a quick call?

Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // UAE Automotive conglomerates — import docs, title, CoO, franchise agreements
  const uae_autodev = `Hi ${first},

UAE automotive conglomerates manage some of the most document-intensive operations in the region — import permits, customs declarations, Certificates of Origin, vehicle title transfers, and franchise agreements all flowing across multiple parties with no cryptographic proof of integrity between handoffs.

With the UAE's broader push toward digital compliance (Dubai Paperless 2026, VARA standards), the question for operations of ${company}'s scale is no longer "should we digitize?" — it's "how do we prove our digital records are unaltered?"

ProofDeed provides field-level blockchain certification for every import and title document at the moment of origination. VIN, chassis number, country of origin, sale price — each individually hashed and anchored. Any post-facto alteration is immediately detectable by any party in the chain, including the Roads and Transport Authority (RTA).

One API. No system replacement. Works alongside your existing DMS and ERP.

See it in 2 minutes: proofdeed.com/demo

Worth a conversation?

Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  const byRole = {
    uae_redev,
    uae_reops,
    uae_legal,
    uae_recx,
    uae_autodev,
  };

  return byRole[role] || uae_redev;
};

// ─────────────────────────────────────────────────────────────────────────────
// SANDBOX / DESIGN PARTNER EMAIL — "Help us define the standard"
// Used for specialized roles where credibility beats a cold pitch.
// Strategy: position them as the expert whose input shapes our API.
// ─────────────────────────────────────────────────────────────────────────────
const SANDBOX_EMAIL = (name, company, role) => {
  const first = name.split(' ')[0];

  const variants = {

    // ── Automotive — title washing / Certificate of Origin / VIN integrity
    auto_remarketing2: {
      subject: `Pilot Opportunity: Cryptographic Vehicle Title Integrity`,
      body: `Hi ${first},

Title washing — where a salvage or lemon title gets laundered through a state transfer — costs dealers and fleet operators billions annually and ends careers when it surfaces post-sale.

We're finalizing the ProofDeed API for vehicle title and resale documentation. We're looking for one Head of Remarketing Operations to act as a Design Partner for our developer sandbox.

The goal: ensure our field-level hashing logic maps perfectly to your resale workflow — sale price, odometer, title status, and VIN history — each anchored to the blockchain at transfer. Cryptographic proof that the record you received is identical to the one that left the OEM.

In exchange for 20 minutes of feedback on our API documentation, you'll get:
→ Early access to our title-fraud detection layer (no cost during sandbox)
→ Direct input into how we model "clean title" for fleet remarketing

Is this worth 20 minutes?

Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`,
    },

    auto_warranty: {
      subject: `Pilot Opportunity: Cryptographic Warranty & Parts Record Verification`,
      body: `Hi ${first},

Falsified service records and fraudulent warranty claims are a documented cost center across every major OEM — and the current workaround (dealer audits, random spot checks) doesn't scale.

We're building the ProofDeed API for automotive warranty and quality documentation. We're looking for one Director of Warranty & Quality Compliance to act as a Design Partner for our developer sandbox.

The goal: ensure our hashing logic maps cleanly to your parts and service record workflow — repair order number, technician ID, parts used, approval timestamp — each individually anchored at creation so any post-facto alteration is immediately detectable.

In exchange for 20 minutes on our API spec, you get:
→ Early access to the parts authenticity layer we're building for IATF 16949 environments
→ Direct influence over how we model "field-level tamper detection" for warranty records

Worth a quick conversation?

Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`,
    },

    auto_dds: {
      subject: `Pilot Opportunity: Cryptographic Document Layer for Dealer Trade-In & Finance Stacks`,
      body: `Hi ${first},

Every DMS — CDK, Reynolds & Reynolds, DealerSocket, Tekion — generates trade-in and financing documents that pass through multiple hands before closing. The current system has no native way to prove a document wasn't altered between creation and signature.

We're finalizing a DMS webhook that certifies each field (VIN, sale price, odometer, buyer name) at the moment of origination. We're looking for one VP of Digital Dealer Solutions to act as a Design Partner for our developer sandbox.

The goal: ensure our integration maps cleanly to your dealer software stack and the F&I workflow your dealers rely on.

In exchange for 20 minutes, you get:
→ The webhook spec + sandbox credentials so your team can evaluate it directly
→ Input into how we model "DMS-native" document locking for trade-ins and floor plan docs

Is this on your radar?

Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`,
    },

    auto_coo: {
      subject: `Pilot Opportunity: Cryptographic Certificate of Origin Verification`,
      body: `Hi ${first},

Certificates of Origin for automotive components are only as reliable as the last person who touched them. Once a CoO leaves the OEM, there's no cryptographic proof it hasn't been altered to misrepresent the component's source — which creates real exposure under country-of-origin compliance requirements.

We're building the ProofDeed API for supply chain document integrity. We're looking for one Supply Chain Transparency Manager to act as a Design Partner for our developer sandbox.

The goal: map our field-level hashing to your CoO workflow — manufacturer, part number, country of origin, certifying officer — so downstream verifiers can confirm the document is unaltered without calling anyone.

In exchange for 20 minutes, you get:
→ Early access to our supply chain verification layer
→ Input into how we model "component origin proof" at scale

Worth a conversation?

Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`,
    },

    auto_blockchain: {
      subject: `Pilot Opportunity: Collaborating on Vehicle Digital Identity Standards`,
      body: `Hi ${first},

Most OEMs are now building some version of a "Vehicle Digital Identity" — a cryptographic record that follows the VIN from factory to end-of-life. The hard problem isn't storage; it's proving that the records accumulated along the way are unaltered originals.

We've built a field-level hashing layer that anchors individual data points (not just document hashes) to the Polygon blockchain at creation. We're looking for one Principal Blockchain Architect in automotive to act as a Design Partner as we finalize our API spec.

The goal: ensure our hashing schema is compatible with how your team models vehicle identity — and share what we've learned about field-level vs. document-level anchoring at OEM scale.

In exchange for 20 minutes, you get sandbox access and early visibility into our roadmap.

Worth a call?

Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`,
    },

    // ── Institutional / Finance / PE
    inst_ethics: {
      subject: `Pilot Opportunity: Cryptographic Data Provenance for Financial Modeling`,
      body: `Hi ${first},

The hardest question in data ethics isn't "was the data biased?" — it's "can you prove the dataset used in this model is identical to the one that was approved?" Once data moves through pipelines, version drift is invisible without a cryptographic anchor at ingestion.

We're finalizing the ProofDeed API for financial data provenance. We're looking for one Chief Data Ethics Officer to act as a Design Partner for our developer sandbox.

The goal: understand how your team currently attests to data integrity in model inputs — and ensure our hashing layer maps to how you define "unaltered" in a financial modeling context.

In exchange for 20 minutes, you get:
→ Sandbox access to our field-level provenance API
→ Direct input into our data ethics use case documentation

Is this worth 20 minutes?

Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`,
    },

    inst_fund: {
      subject: `Pilot Opportunity: Cryptographic LP Document Integrity`,
      body: `Hi ${first},

Subscription documents and LP reports pass through fund administrators, GPs, LPs, and legal — each handoff a moment where "was this altered?" becomes unanswerable without native proof. LP disputes over document versions are slow, expensive, and reputationally damaging.

We're building the ProofDeed API for fund administration document integrity. We're looking for one Head of Fund Administration to act as a Design Partner for our developer sandbox.

The goal: map our field-level hashing to your subscription and reporting workflow so LPs can independently verify the document they received is identical to what was sent — without a phone call.

In exchange for 20 minutes:
→ Sandbox access + API spec tailored to fund administration documents
→ Input into how we model "LP document proof" at scale

Worth exploring?

Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`,
    },

    inst_ma: {
      subject: `Pilot Opportunity: Cryptographic Data Room Document Integrity`,
      body: `Hi ${first},

Your team spends weeks in data rooms verifying that what you're seeing is what the seller actually produced. But there's no native way to prove a document hasn't been altered since it was originally uploaded — which means you're relying on trust at the moment you can least afford to.

We're finalizing the ProofDeed API for M&A document integrity. We're looking for one Managing Director of Due Diligence to act as a Design Partner for our developer sandbox.

The goal: understand your current data room workflow and ensure our field-level anchoring maps to how you define "original document" during diligence — financials, material contracts, IP schedules, representations.

In exchange for 20 minutes:
→ Sandbox access to our verification API (plug-in to any existing VDR)
→ Input into how we pitch this to deal teams

Worth a conversation?

Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`,
    },

    inst_aml: {
      subject: `Pilot Opportunity: Cryptographic Proof of Source-of-Funds Documentation`,
      body: `Hi ${first},

AML compliance depends entirely on the integrity of source-of-funds documentation — but once a wire confirmation, bank statement, or ownership certificate is submitted, there's no cryptographic way to prove it wasn't altered before it hit your review queue.

We're building the ProofDeed API for immutable AML document proof. We're looking for one Chief Compliance & AML Officer to act as a Design Partner for our developer sandbox.

The goal: ensure our field-level hashing maps to your source-of-funds review workflow — document type, submission timestamp, reviewer chain — so you have cryptographic proof of what was submitted, not just what was stored.

In exchange for 20 minutes:
→ Sandbox access + compliance documentation for 31 CFR / FinCEN audit scenarios
→ Input into how we model "immutable submission proof" for AML workflows

Is this on your radar?

Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`,
    },

    inst_digital_assets: {
      subject: `Pilot Opportunity: Bridging Traditional Document Integrity with Cryptographic Proof`,
      body: `Hi ${first},

The core challenge in digital assets regulation isn't the assets — it's proving that the traditional documentation supporting them (ownership records, transfer agreements, KYC packages) hasn't been altered between creation and submission to regulators.

We're finalizing the ProofDeed API for cross-asset document provenance. We're looking for one Head of Digital Assets Regulatory to act as a Design Partner for our developer sandbox.

The goal: understand how your team currently bridges traditional asset documentation and cryptographic attestation — and ensure our anchoring layer maps cleanly to your regulatory submission workflow.

In exchange for 20 minutes:
→ Sandbox access to our blockchain anchoring API
→ Input into how we model "regulatory-grade" document proof for digital asset compliance

Worth exploring?

Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`,
    },

    // ── Pharma / Life Sciences — deep GXP / lab / logistics
    pharma_gxp: {
      subject: `Pilot Opportunity: Cryptographic GXP Document Integrity (ALCOA+ Alignment)`,
      body: `Hi ${first},

FDA 483 observations and warning letters increasingly cite "data integrity failures" — not missing records, but records that can't be proven unaltered since creation. ALCOA+ requires Attributable, Legible, Contemporaneous, Original, Accurate — and the "Original" requirement is the one no current QMS can cryptographically prove.

We're finalizing the ProofDeed API for GXP document integrity. We're looking for one VP of Quality Systems to act as a Design Partner for our developer sandbox.

The goal: ensure our field-level hashing logic maps correctly to your GxP document workflow — batch records, deviations, SOPs, audit trails — each field individually anchored at creation per 21 CFR Part 11.

In exchange for 20 minutes:
→ Sandbox access + our 21 CFR Part 11 / ALCOA+ compliance documentation
→ Direct input into how we define "original document proof" across GLP, GMP, and GCP contexts

Worth 20 minutes with your QA team?

Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`,
    },

    pharma_trial: {
      subject: `Pilot Opportunity: Cryptographic Raw Data Integrity for Clinical Trials`,
      body: `Hi ${first},

The most sensitive moment in clinical data management is the line between "raw data" and "cleaned data" — and regulators want proof that raw data was never altered inappropriately before cleaning. Right now, that proof is a process attestation, not a cryptographic one.

We're building the ProofDeed API for clinical trial data provenance. We're looking for one Head of Clinical Trial Data Management to act as a Design Partner for our developer sandbox.

The goal: understand how your team currently attests to raw data integrity — and ensure our field-level anchoring maps to your EDC/CDMS workflow so you have cryptographic proof of what was collected at the source.

In exchange for 20 minutes:
→ Sandbox access tailored to clinical data collection workflows
→ Input into how we model "pre-cleaning data lock" for ICH E6 (GCP) environments

Is this worth a conversation?

Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`,
    },

    pharma_serial: {
      subject: `Pilot Opportunity: Cryptographic Digital Fingerprint for Drug Serialization`,
      body: `Hi ${first},

DSCSA Track & Trace gives every drug package a serialized identifier — but the identifier only proves what the package is, not that the documentation accompanying it is unaltered. Counterfeit products with valid serial numbers are the next wave.

We're finalizing the ProofDeed API for pharmaceutical product serialization integrity. We're looking for one Director of Product Serialization to act as a Design Partner for our developer sandbox.

The goal: ensure our hashing layer maps to your serialization workflow — lot number, GTIN, expiration, manufacturer site — so downstream verifiers can confirm the documentation matches the physical package.

In exchange for 20 minutes:
→ Sandbox access + DSCSA / GS1 alignment documentation
→ Input into how we model "document-to-package binding" at serialization scale

Worth exploring?

Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`,
    },

    pharma_lims: {
      subject: `Pilot Opportunity: Cryptographic Audit Trail for LIMS Document Workflows`,
      body: `Hi ${first},

Every LIMS generates audit trails — but those audit trails live inside the system and can't be independently verified by a regulator, customer, or auditor without trusting the system itself. When a 483 cites "audit trail questions," you're defending a log, not a proof.

We're building the ProofDeed API to add a blockchain-anchored audit layer on top of existing LIMS workflows. We're looking for one LIMS Administrator to act as a Design Partner for our developer sandbox.

The goal: understand how your LIMS currently generates and exports audit records — and where our anchoring API can slot in without replacing your existing system.

In exchange for 20 minutes:
→ Sandbox access + integration notes for common LIMS platforms (LabVantage, STARLIMS, LabWare)
→ Input into how we design our LIMS connector

Is this worth a quick call?

Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`,
    },

    pharma_coldchain: {
      subject: `Pilot Opportunity: Cryptographic Integrity for Cold-Chain Shipping Logs`,
      body: `Hi ${first},

Cold-chain integrity failures — where a temperature excursion happens but the shipping log is "corrected" before it reaches QA — are a known fraud vector in pharmaceutical logistics. Once the log leaves the sensor system, there's no native proof it wasn't altered.

We're finalizing the ProofDeed API for pharma logistics document integrity. We're looking for one CTO in pharmaceutical logistics to act as a Design Partner for our developer sandbox.

The goal: ensure our field-level anchoring maps to your cold-chain logging workflow — sensor readings, shipment ID, excursion timestamps, chain-of-custody — so QA receives cryptographic proof that the record is exactly what the sensor generated.

In exchange for 20 minutes:
→ Sandbox access + IoT-to-blockchain anchoring documentation
→ Input into how we model "sensor-to-record integrity" for GDP compliance

Worth exploring?

Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`,
    },

    // ── Aviation / MRO — airworthiness / SMS / records
    aviation_airworthy: {
      subject: `Pilot Opportunity: Cryptographic Airworthiness Paper Trail Integrity`,
      body: `Hi ${first},

An airworthiness release is the final signature in a paper trail that spans MRO shops, parts suppliers, and airline maintenance teams. If any document in that chain was altered — work order, parts tag, Form 8130-3 — your signature is on a fraudulent release. And the current paper trail offers no cryptographic proof.

We're finalizing the ProofDeed API for airworthiness documentation. We're looking for one Director of Airworthiness to act as a Design Partner for our developer sandbox.

The goal: ensure our field-level hashing maps to your release workflow — work scope, authorized certifier, component sign-offs — so you have provable, independently verifiable documentation at every step before your signature.

In exchange for 20 minutes:
→ Sandbox access + FAA Order 8300.10 / EASA Part-145 alignment documentation
→ Direct input into how we model "release chain integrity"

Worth a quick conversation?

Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`,
    },

    aviation_logistics: {
      subject: `Pilot Opportunity: Cryptographic Rotatable Parts Documentation Integrity`,
      body: `Hi ${first},

Rotatable components change hands dozens of times across their service life. Each handoff requires documentation — Form 8130-3, teardown reports, overhaul records — and each handoff is a moment where a document can be altered to misrepresent an unserviceable part as airworthy.

We're building the ProofDeed API for component support documentation. We're looking for one VP of Component Support & Logistics to act as a Design Partner for our developer sandbox.

The goal: map our field-level anchoring to your rotatable parts documentation workflow so every Form 8130-3 and overhaul report carries cryptographic proof of its original state.

In exchange for 20 minutes:
→ Sandbox access tailored to MRO parts documentation
→ Input into how we model "birth certificate integrity" for rotatable components

Is this on your radar?

Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`,
    },

    aviation_cdo: {
      subject: `Pilot Opportunity: Cryptographic Integrity for Electronic Technical Logs`,
      body: `Hi ${first},

The transition from paper logbooks to eTechLogs introduces a new risk: digital records are easier to alter than paper ones, and the current eTechLog platforms don't natively anchor records to an immutable external proof. If a log entry is edited, there's no way to detect it without a system audit.

We're building the ProofDeed API to add a blockchain integrity layer to existing eTechLog workflows. We're looking for one Chief Digital Officer in MRO to act as a Design Partner for our developer sandbox.

The goal: understand how your current eTechLog system generates and stores records — and identify where our anchoring API fits without replacing your platform.

In exchange for 20 minutes:
→ Sandbox access + eTechLog integration documentation
→ Input into how we model "immutable log entry" for CAMP / Ultramain / AMOS environments

Worth a call?

Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`,
    },

    aviation_sms: {
      subject: `Pilot Opportunity: Cryptographic Integrity for Safety Incident Reports`,
      body: `Hi ${first},

The value of a Safety Management System depends entirely on the integrity of its data. If an incident report can be quietly edited after submission — changing severity ratings, removing witnesses, adjusting timelines — the SMS becomes a liability shield instead of a safety tool.

We're finalizing the ProofDeed API for aviation safety data integrity. We're looking for one Aviation SMS Lead to act as a Design Partner for our developer sandbox.

The goal: ensure our anchoring logic maps to your incident report workflow — reporter ID, event timestamp, severity classification, contributing factors — so every submitted report is cryptographically locked at the moment of filing.

In exchange for 20 minutes:
→ Sandbox access + ICAO Annex 19 / FAA SMS alignment documentation
→ Input into how we model "immutable incident report" for regulatory audit scenarios

Worth a conversation?

Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`,
    },

    aviation_records: {
      subject: `Pilot Opportunity: Cryptographic Fleet Technical Records Integrity`,
      body: `Hi ${first},

A fleet's technical records — birth certificates, Form 8130-3s, major repair/alteration records — are the legal proof that every aircraft is airworthy. When those records are questioned (during an audit, a sale, or an incident investigation), the burden is on you to prove they're unaltered originals. Right now, that proof doesn't exist natively.

We're finalizing the ProofDeed API for fleet technical records. We're looking for one Head of Fleet Technical Records to act as a Design Partner for our developer sandbox.

The goal: ensure our field-level hashing maps perfectly to your technical records workflow — aircraft registration, form type, certifying authority, date of issue — so every record carries cryptographic proof of its original state.

In exchange for 20 minutes:
→ Sandbox access + FAA AC 120-78B / EASA alignment documentation
→ Input into how we model "birth certificate integrity" at fleet scale

Worth a conversation?

Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`,
    },
  };

  const v = variants[role];
  if (v) return v.body;

  // Fallback — generic sandbox hook
  return `Hi ${first},

We're in the final stages of building the ProofDeed API for document integrity verification. We're looking for one ${role.replace(/_/g,' ')} at a ${company}-sized organization to act as a Design Partner for our developer sandbox.

In exchange for 20 minutes of feedback on our API specification, you get early access to our blockchain document verification layer — and direct input into how we build for your industry.

Worth a conversation?

Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;
};

const INITIAL_EMAIL = (name, company, industry, role) => {
  const rawFirst = name.split(' ')[0];
  // Guard: never greet as "Hi Team," — use title-cased first name only if it looks real
  const first = /^(team|unknown|contact|info|null|undefined)$/i.test(rawFirst) ? company.split(' ')[0] : rawFirst;

  // ── Recorder / Clerk — "Prove document integrity when records are challenged"
  const recorder = `Hi ${first},

When a recorded document gets challenged — contested deed, disputed filing, chain-of-title dispute — your office has to prove it. The question isn't whether it's in your system. It's whether you can prove it hasn't been altered.

ProofDeed creates a Trust Record for every document at the moment of recording — a permanent, tamper-proof fingerprint anchored to the Polygon blockchain. If the document is ever questioned, authenticity is provable in seconds. No system replacement. No document storage. No IT required. Works alongside your existing workflow — live in days.

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

ProofDeed creates a Trust Record at the moment a document is processed — permanently anchored to the Polygon blockchain, independently verifiable by any court, auditor, or opposing counsel without access to your internal systems. Legally defensible under FRE Rule 901. No system changes required.

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

ProofDeed adds tamper-proof Trust Records to your existing document workflow — no system replacement, no document storage on our end, single API call. Most county offices are live in under a week with no impact on existing infrastructure.

It creates a blockchain-anchored Trust Record for each document at the moment it's processed — permanently verifiable proof of integrity and timestamp that holds up in court under FRE Rule 901.

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

ProofDeed offers a fixed-cost 45-day Government Pilot — full API access, no variable costs, no long-term commitment. If it works, you continue on a monthly subscription. If not, your Trust Records remain on-chain permanently regardless.

It anchors documents to the Polygon blockchain at the moment of processing — tamper-proof, legally defensible proof under FRE Rule 901. Single API integration. No system replacement.

ACH and purchase order accepted.

See it in 2 minutes: proofdeed.com/demo

Worth a quick call to discuss the pilot structure?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
gov@proofdeed.com | proofdeed.com`;

  // ── Auto Dealer / F&I / Title — "proof of ownership + transaction integrity"
  const auto_dealer = `Hi ${first},

Every title transfer, lien release, and odometer disclosure your operation processes is a liability the moment it's disputed. A forged title or altered sale price — if you can't prove the document at the exact moment it was created, you're defending yourself without evidence.

ProofDeed creates a Trust Record for every deal document — VIN, odometer, sale price, buyer name — anchored individually on the Polygon blockchain when the deal is finalized. If a single field is ever moved, it's immediately detectable. Buyers get a permanent Asset Passport™ to verify their vehicle's history. You get legally defensible proof under FRE Rule 901.

No system replacement — one webhook into your existing DMS, live in a day.

See it in 2 minutes: proofdeed.com/demo

Worth a 20-minute call this week?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── Auto Lender / Collateral / Lien — "lien accuracy + title chain integrity"
  const auto_lender = `Hi ${first},

Lien accuracy and title chain integrity are the foundation of your collateral position. When a borrower defaults and the title history is challenged — altered lien amounts, forged releases, disputed ownership — your recovery depends on whether you can prove each field in the document is authentic.

ProofDeed creates a Trust Record for every loan document and lien at the field level — VIN, lien amount, lienholder, release date — each individually anchored on the Polygon blockchain. If a single figure is altered after the fact, it's immediately provable. Legally defensible under FRE Rule 901. One API call, no system changes.

See it in 2 minutes: proofdeed.com/demo

Would 20 minutes be worth it?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── Auto Auction / Remarketing — "chain of custody for high-volume transfers"
  const auto_auction = `Hi ${first},

At auction volume, every vehicle transfer is a potential chain-of-custody dispute. Odometer fraud, salvage title laundering, forged condition reports — the liability lands on whoever processed the last transaction without proof.

ProofDeed creates a Trust Record for every vehicle sale — VIN, odometer, condition grade, seller/buyer fields — anchored on the Polygon blockchain at the moment of transaction. Each buyer gets an Asset Passport™ showing the vehicle's verified history. Title washing becomes immediately detectable.

Legally defensible under FRE Rule 901. One webhook into your existing workflow, live in a day.

See it in 2 minutes: proofdeed.com/demo

Worth a quick call?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── Institutional Compliance / Records / GRC — "audit-proof document integrity"
  const inst_compliance = `Hi ${first},

When an audit, dispute, or regulatory review puts a document's authenticity in question, your organization has to prove it — not just that it exists in your system, but that it hasn't been altered since it was created. Most document management systems can't answer that. Courts and regulators increasingly expect independent proof.

ProofDeed creates a Trust Record for every critical document at the moment it's processed — permanently anchored to the Polygon blockchain, independently verifiable by any court or regulator without access to your internal systems. Legally defensible under FRE Rule 901. No system replacement. No document storage. Single API call.

See it in 2 minutes: proofdeed.com/demo

Worth a 20-minute conversation?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── Institutional Legal / Risk — "verifiable proof for disputes and regulatory reviews"
  const inst_legal = `Hi ${first},

When document authenticity is disputed in litigation or a regulatory review, the question is simple: can you prove this document is unchanged from when it was created? Metadata in your DMS won't hold up. A court wants independent, tamper-proof evidence.

ProofDeed creates a Trust Record for every critical document at the moment it's processed — independently verifiable by any court or regulator without access to your internal systems. Legally defensible under FRE Rule 901. No system changes required.

The cost of a single disputed document in litigation dwarfs the annual cost of protecting against it.

See it in 2 minutes: proofdeed.com/demo

Worth a quick call?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── Healthcare — "tamper-proof EHR + compliance audit trail"
  const inst_healthcare = `Hi ${first},

When a patient record, prescription, or clinical document gets disputed — in litigation, a federal audit, or a CMS review — your organization has to prove it hasn't been altered. Most EHR systems log who accessed a record. None of them can prove the content hasn't changed since it was created.

With AI tools now capable of altering scanned documents without a trace, that gap is a liability. Under HIPAA, CMS, and Joint Commission standards, document integrity isn't optional — but most compliance programs have no independent proof layer.

ProofDeed creates a Trust Record for each clinical document at the moment it's processed — patient name, dates, clinical data, all individually anchored to the Polygon blockchain. If a single field is changed after the fact, it's immediately detectable. Legally defensible under FRE Rule 901. No system replacement.

See it in 2 minutes: proofdeed.com/demo

Would a 20-minute call make sense this week?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── Title & Escrow — "make every closing document provable and tamper-proof"
  const title_escrow = `Hi ${first},

Every real estate closing generates documents that can be disputed years later — deeds, settlement statements, wire instructions. The problem most agencies don't realize: standard PDFs can be altered after signing without triggering any alert, making it impossible to prove what was in the document at the moment of closing.

ProofDeed creates a Trust Record for every closing document the instant it's processed — buyer name, sale price, legal description, recording date, all individually locked on the Polygon blockchain. If a single field is ever changed, it's immediately detectable. Buyers get a permanent verification link. You get legally defensible proof under FRE Rule 901.

No software to install. No IT required. Works alongside your existing closing platform. Live in a day.

See it in 2 minutes: proofdeed.com/demo

Worth a 20-minute call this week?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── Legal / Law Firms — "lock document integrity at creation so it holds up in court"
  const legal_firm = `Hi ${first},

With AI editing tools and deepfake technology now capable of altering signed documents without a trace, proving the exact date and authenticity of a deed, will, or trust in court has become a serious liability for estate and real estate attorneys.

The most damaging thing opposing counsel can do is allege a document was altered after creation — and if you can't prove otherwise independently, you're defending the document instead of the case.

ProofDeed creates a Trust Record for every firm document — party names, dates, amounts, terms — each individually anchored on the Polygon blockchain at the moment of creation. Documents become legally defensible under FRE Rule 901. If opposing counsel claims anything was changed after signing, you prove it in seconds.

No system changes. No IT required.

See it in 2 minutes: proofdeed.com/demo

Would 20 minutes make sense?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── Insurance (non-auto) — "prove claim documents haven't been altered"
  const insurance_gen = `Hi ${first},

Insurance fraud schemes succeed because claim photos, damage estimates, and loss documentation are easy to alter before submission — and by the time your SIU team investigates, there's no way to prove what the original showed. Photoshopped damage, inflated repair estimates, backdated reports: the manipulation happens before it ever reaches your desk.

ProofDeed lets your field adjusters create a Trust Record for claim photos and repair estimates the second they're captured — making it impossible for claimants to alter values after the fact. Each Trust Record is permanently anchored to the Polygon blockchain, legally defensible under FRE Rule 901. No app for claimants. Single API call for your adjusters.

Live in days.

See it in 2 minutes: proofdeed.com/demo

Worth a 20-minute call with your SIU or claims team?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── Construction & Lien — "ensure lien and waiver documents can't be challenged later"
  const construction = `Hi ${first},

Mechanic's liens, lien waivers, and release documents are among the most frequently disputed in construction litigation. A conditional waiver that looks like an unconditional one. A lien release with an altered amount. When the dispute hits, whoever processed the document has to prove it.

ProofDeed creates a Trust Record for every lien and contract document at the moment it's signed — permanent, tamper-proof proof of the exact document at the exact time, legally defensible under FRE Rule 901. No system replacement. Single API call.

See it in 2 minutes: proofdeed.com/demo

Would 20 minutes be worth it?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── Supply Chain / Logistics — "Bill of Lading fraud + cargo-cloning prevention"
  const supply_chain = `Hi ${first},

Freight cargo theft and bill of lading fraud cost carriers billions annually — not because systems fail, but because PDF and digital documents can be altered in transit without leaving a trace. By the time a shipment dispute reaches your legal team, it's impossible to prove which version of the document is original.

ProofDeed creates a Trust Record for every Bill of Lading at the origin point — stopping cargo-cloning and chain-of-custody fraud before it reaches the destination gate. Every Trust Record is permanently verifiable, legally defensible under FRE Rule 901. No system replacement. Single API call. Live in days.

See it in 2 minutes: proofdeed.com/demo

Worth a 20-minute call this week?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── Academic / Professional Credentialing — "un-copyable digital credentials"
  const credentialing = `Hi ${first},

Diploma mills and credential fraud cost employers millions annually — and the institutions that issued the credentials bear reputational liability they didn't create. The problem: most verification systems require checking back with your office. If your records system is unavailable, or a credential is forged entirely, there's no independent proof.

ProofDeed turns diplomas and certificates into permanent Trust Records — anchored to the Polygon blockchain at issuance. Employers self-verify for free without contacting your office. No forged document can replicate the cryptographic proof. Legally defensible under FRE Rule 901.

No records system replacement. Live in days.

See it in 2 minutes: proofdeed.com/demo

Worth a 20-minute call?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── International Government Archives — vendor-independent preservation
  const intl_archives = `Hi ${first},

Government records outlive the software they were created in. When a vendor changes platforms, loses a contract, or shuts down — the records remain, but the ability to independently verify their integrity often doesn't. Future courts, auditors, and citizens need proof that doesn't depend on your current system still being operational.

ProofDeed creates a permanent Trust Record for every document at the moment it's processed — independently verifiable by any court, auditor, or records requester worldwide, regardless of what happens to your internal infrastructure over time. When systems migrate, the proof stays with the record permanently.

Single API integration. Live in days.

See it in 2 minutes: proofdeed.com/demo

Worth a 20-minute conversation?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── Global Law Firms — eDiscovery chain of custody + AI document tampering
  const global_law_firm = `Hi ${first},

Document authenticity disputes are becoming the defining issue in complex litigation. With AI tools now capable of altering signed contracts, executed agreements, and court-filed documents without a trace, opposing counsel has a new attack vector: allege the document was modified after execution and force the producing party to prove otherwise.

Most firms have eDiscovery infrastructure for finding and producing documents. Very few have independent, tamper-proof chain of custody starting at the moment of document creation — the layer that shuts down authenticity challenges in seconds rather than defending them for months.

ProofDeed creates a Trust Record at the moment any document is processed — independently verifiable by any court globally without access to your internal systems. No system replacement. Can be white-labeled or recommended to clients as a document integrity standard.

See it in 2 minutes: proofdeed.com/demo

Worth a 20-minute call with your innovation or eDiscovery team?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── Global Insurance — international claims fraud + field adjuster fingerprinting
  const global_insurance = `Hi ${first},

Insurance fraud schemes succeed because claim photos, damage estimates, and loss documentation are easy to alter before submission. By the time your investigation team reviews a claim, the original record may be unrecoverable. Inflated repair estimates, backdated reports, and photoshopped damage photos — the manipulation happens before the document reaches your desk.

ProofDeed lets field adjusters create a Trust Record for claim photos and repair estimates at the moment they are captured — making it impossible to alter values after the fact. Each Trust Record is permanently anchored to the Polygon blockchain, independently verifiable by any court or regulator worldwide. No app for claimants. Single API call for your adjusters.

Live in days.

See it in 2 minutes: proofdeed.com/demo

Worth a 20-minute call with your claims or fraud team?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── Blockchain/Tech Companies — partnership/integration angle
  const blockchain_partner = `Hi ${first},

Your platform provides the infrastructure. The missing layer most enterprise clients ask for next is legal admissibility — the ability to prove a specific document or record is unchanged at a specific moment in time, in a way that holds up in US courts under FRE Rule 901 without requiring a judge to understand distributed ledgers.

ProofDeed handles that last mile. We create a Trust Record anchored to Polygon at the moment documents are processed — legally defensible proof that complements what your platform does, not a competitor. Several of our conversations with enterprise buyers start because they already have blockchain infrastructure but need the trust layer on top of it.

If there's a partnership, integration, or referral channel that makes sense, I'd like to explore it.

See it in 2 minutes: proofdeed.com/demo

Worth a 20-minute call?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── Automotive OEM — supply chain parts traceability + recall documentation
  const auto_oem = `Hi ${first},

When a recall investigation, parts fraud claim, or autonomous vehicle incident goes to litigation, your supply chain documentation has to prove authenticity — not just that it's in your systems, but that it hasn't been altered since it was created. Falsified Certificates of Conformity, altered build sheets, and tampered OTA firmware version records all start with a document that couldn't be independently verified.

ProofDeed creates a Trust Record for every supply chain document and parts certification at the moment it's generated — part number, supplier ID, conformity date, firmware hash, all individually locked on the Polygon blockchain. If any field is changed downstream, it's immediately detectable. Each record gets a permanent Asset Passport™ with public verification. Legally defensible under FRE Rule 901.

No system replacement. Single webhook into your existing document workflow.

See it in 2 minutes: proofdeed.com/demo

Worth a 20-minute call this week?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── IP / R&D / Tech — "prior-art timestamp without revealing trade secrets"
  const ip_timestamp = `Hi ${first},

In patent disputes and trade secret litigation, the first question is always: who created this first, and can they prove it independently? Invention disclosures dated in internal systems don't hold up in court — judges want proof that wasn't controlled by the party claiming priority.

ProofDeed creates a Trust Record for your code, design files, or trade secret documents at the moment they're created — securing bulletproof prior-art proof without exposing the contents. The cryptographic fingerprint is anchored to a public blockchain. If ownership is ever challenged, you prove creation date in seconds, legally defensible under FRE Rule 901.

No document storage on our end. Takes minutes to integrate.

See it in 2 minutes: proofdeed.com/demo

Would 20 minutes make sense?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── Regulated Industries — "audit-proof regulatory records"
  const regulated = `Hi ${first},

When a regulator or auditor challenges a compliance document — an environmental filing, a pharma submission, an energy report — the question isn't just whether you have it. It's whether you can prove it hasn't been altered since it was filed.

ProofDeed creates a Trust Record for every regulatory document at the moment it's submitted — independently verifiable proof of integrity and timestamp, legally defensible under FRE Rule 901. No system replacement. No document storage. Single API call.

See it in 2 minutes: proofdeed.com/demo

Would 20 minutes make sense this week?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── Accounting / Audit — "evidence assurance layer"
  const accounting = `Hi ${first},

Audit work depends on document integrity — but auditors verify what clients provide, not whether the underlying documents have been altered before they arrive. When an audit is challenged or a fraud surfaces, the question is whether the documents your team reviewed were the originals.

ProofDeed creates a Trust Record at the moment a document is created — independently verifiable proof that it hasn't been altered since. Not a replacement for your process — a trust layer underneath it.

See it in 2 minutes: proofdeed.com/demo

Worth a 20-minute conversation?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── Private Equity / M&A — "lock deal documents at every stage"
  const pe_ma = `Hi ${first},

In M&A and PE deals, documents change hands across dozens of parties over months. By the time a dispute surfaces — a rep and warranty claim, a contested disclosure, a post-close disagreement — the question is which version of the document was signed and when. If you can't prove it independently, you're litigating the paper trail instead of the deal.

ProofDeed creates a Trust Record for every deal document at each stage — permanent, tamper-proof proof of the exact document at the exact time, legally defensible under FRE Rule 901. No system replacement. Single API call.

See it in 2 minutes: proofdeed.com/demo

Worth a quick call?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── PE / Institutional COO — back-office document workflow integrity
  const inst_coo = `Hi ${first},

In private equity and asset management, the back office handles documents where a single altered digit can cost millions — subscription agreements, side letters, PPMs, capital call notices. Most document systems can tell you when a file was last modified. None can prove it wasn't.

ProofDeed creates a Trust Record for every critical document at the field level — investor name, commitment amount, terms, execution date — each individually anchored on the Polygon blockchain at the moment of execution. If a single decimal point is moved after the fact, it's immediately detectable. Independent proof that doesn't rely on your internal IT.

Integrates via API into your existing document workflow. No system replacement. Live in a day.

See it in 2 minutes: proofdeed.com/demo

Worth a 20-minute conversation?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── Head of Investor Relations — LP document security
  const inst_ir = `Hi ${first},

When an LP questions whether the subscription agreement or capital account statement they received is exactly what was executed — your word against theirs without an independent record.

ProofDeed creates a Trust Record for every LP document at the field level — commitment amount, terms, execution date — each individually anchored on the blockchain at the moment it's sent. LPs can verify their own records independently without accessing your systems. If anything was altered in transit or after the fact, it's immediately provable.

Third-party verified. Auditors accept it. Regulators expect it. One API call, no system changes.

See it in 2 minutes: proofdeed.com/demo

Would a brief call make sense?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── General Counsel / CCO — SEC audit trail
  const inst_gcc = `Hi ${first},

SEC examiners and regulators increasingly ask whether audit trails are immutable — not just whether you have records, but whether those records can be proven unaltered since creation. When a compliance document is questioned in an examination, "we have it on file" is not the same as "we can prove it hasn't changed."

ProofDeed creates a Trust Record for every compliance document at the moment it's filed — independently verifiable proof of integrity and timestamp, legally defensible under FRE Rule 901.

See it in 2 minutes: proofdeed.com/demo

Worth 20 minutes this week?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── Director of Due Diligence — verify documents provided by targets
  const inst_dd = `Hi ${first},

In due diligence, you're reviewing documents provided by the target — financials, contracts, IP filings, compliance records. You have no way to verify those documents are the originals and haven't been altered before they reached you. When a rep and warranty claim surfaces post-close, that's exactly the question.

ProofDeed lets counterparties anchor documents to the blockchain at the moment they're created — so when you receive them in diligence, you can verify independently that they're unaltered originals. Turns document integrity from an assumption into a proof.

See it in 2 minutes: proofdeed.com/demo

Worth a quick call?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── Pharma QA/QC — ALCOA+ data integrity, CoA tamper detection
  const pharma_qa = `Hi ${first},

FDA and EMA are tightening enforcement of ALCOA+ data integrity standards — and the most common failure point isn't missing records, it's records that can't be proven unaltered. A Certificate of Analysis, a batch manufacturing record, a deviation report — if you can't prove the document hasn't been modified since creation, the entire batch is at risk.

ProofDeed creates a Trust Record for every quality document at the field level — batch number, test results, analyst signature, approval date — each individually anchored on the Polygon blockchain at the moment of creation. If a single value is changed after the fact, it's immediately detectable. Third-party proof that satisfies 21 CFR Part 11 and ALCOA+ without replacing your QMS.

One API call. No system replacement. Live in a day.

See it in 2 minutes: proofdeed.com/demo

Worth 20 minutes with your QA team?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── Pharma CCO / Regulatory Affairs — FDA audit trail
  const pharma_cco = `Hi ${first},

When the FDA or EMA audits your data integrity, the question isn't just whether records exist — it's whether those records can be proven unaltered since creation. ALCOA+ requires that every data point be attributable, legible, contemporaneous, original, and accurate. "We have it in our system" doesn't satisfy the original requirement.

ProofDeed creates a Trust Record for every regulatory document at the moment it's filed — tamper-proof, independently verifiable proof under 21 CFR Part 11 and legally defensible under FRE Rule 901. Third-party verified, not dependent on your internal IT.

One API call into your existing document workflow. No system replacement.

See it in 2 minutes: proofdeed.com/demo

Worth a brief conversation this week?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── Pharma Supply Chain — serialization + track and trace
  const pharma_supply = `Hi ${first},

The Certificate of Analysis travels from factory to pharmacy through multiple hands. If a CoA is altered at any point in the chain — test results adjusted, batch numbers changed — the tampered document looks identical to the original. Serialization systems track the package. They don't prove the document inside it is unaltered.

ProofDeed creates a Trust Record for every CoA and supply chain document at the field level at the moment of creation — independently verifiable proof that what arrived at the pharmacy is exactly what left the factory. One webhook into your existing serialization workflow.

See it in 2 minutes: proofdeed.com/demo

Would a quick call make sense?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── Pharma Clinical — trial data integrity
  const pharma_clinical = `Hi ${first},

Post-market scrutiny of clinical trial data increasingly focuses on whether patient data was "cleaned" or modified after collection. If a regulator or opposing counsel alleges data manipulation, the question is whether you can prove every data point is unchanged from the moment it was recorded.

ProofDeed creates a Trust Record for every clinical data point — patient ID, measurement, date, site — each individually anchored on the blockchain at the moment of entry. Any modification after the fact is immediately detectable and independently provable. Satisfies 21 CFR Part 11 without replacing your EDC system.

See it in 2 minutes: proofdeed.com/demo

Worth 20 minutes to walk through the integration?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── Aviation DOM / Safety — maintenance log integrity
  const aviation_dom = `Hi ${first},

In aviation, a plane is only as airworthy as its paperwork. When an incident investigation or airworthiness authority challenges a maintenance log — whether an inspection was actually signed off on that date, whether a part was genuinely certified — the documentation is the evidence. If it can't be proven unaltered, the liability is open.

ProofDeed creates a Trust Record for every maintenance log entry at the field level — tail number, inspection type, technician ID, sign-off date, part number — each individually anchored on the Polygon blockchain at the moment it's recorded. If a single field is ever modified, it's immediately detectable. Legally defensible under FRE Rule 901.

One webhook into your MRO management system. No system replacement.

See it in 2 minutes: proofdeed.com/demo

Worth a brief conversation?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── Aviation CTO / Digital Transformation — MRO records digitization
  const aviation_cto = `Hi ${first},

As MRO operations move from paper to digital, the core question regulators and airlines ask is: how do you prove a digitized record is identical to the original, and that it hasn't been altered since? Paper had a physical chain of custody. Digital records need cryptographic proof.

ProofDeed provides that proof layer. Every maintenance record, parts certificate, and airworthiness document gets a Trust Record anchored to the Polygon blockchain at the moment it's created or digitized — independently verifiable by any airline, regulator, or auditor without access to your systems.

One API call into your existing document workflow.

See it in 2 minutes: proofdeed.com/demo

Worth 20 minutes?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── Aviation Parts — anti-counterfeit birth certificates
  const aviation_parts = `Hi ${first},

Bogus parts are the single biggest undetected risk in aviation maintenance. A counterfeit part looks identical to a certified one — until it fails. The FAA estimates 2% of installed parts in service are unapproved. The only way to close that gap is to make the paper trail unforgeable.

ProofDeed creates a permanent Asset Passport™ for every certified part at the moment it leaves the manufacturer — part number, serial number, manufacturer, test certification, date — each field individually anchored on the blockchain. Any document presented later can be verified against the original in seconds. Counterfeit parts can't pass verification.

One API call for manufacturers. One verification link for MRO teams.

See it in 2 minutes: proofdeed.com/demo

Worth a quick conversation?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── Auto OEM Supply Chain — VIN-linked document integrity
  const auto_supply = `Hi ${first},

From supplier Certificates of Conformity to VIN-linked build sheets, your supply chain documentation is the proof that a vehicle's history is clean. Title washing, falsified maintenance records, and altered part certifications all start with a document someone couldn't prove original.

ProofDeed creates a Trust Record for each field in your supply chain documents — part number, supplier ID, conformity date, test results — individually anchored on the Polygon blockchain at the moment they're created. If any field is altered downstream, it's immediately detectable. Each document gets an Asset Passport™ with a public verification link tied to the VIN.

One webhook into your existing document workflow. No system replacement. Live in a day.

See it in 2 minutes: proofdeed.com/demo

Worth a quick conversation?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── Auto CDO — Digital Twin integrity
  const auto_cdo = `Hi ${first},

The Digital Twin is only as reliable as the documents behind it. If a maintenance log, inspection record, or build sheet can be altered without detection, the twin reflects a history that may not be real — and the liability follows the OEM.

ProofDeed creates a Trust Record for every document in the vehicle's lifecycle at the moment it's created. The digital fingerprint is permanent, VIN-linked, and independently verifiable. If anything changes downstream, it's immediately provable.

See it in 2 minutes: proofdeed.com/demo

Worth 20 minutes to explore?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── Auto Remarketing / Fleet — title and service record integrity
  const auto_remarketing = `Hi ${first},

When you're moving thousands of vehicles through remarketing channels, the title and service record documentation is what determines resale value — and liability exposure. A single document dispute on a fleet vehicle can unwind an entire transaction.

ProofDeed creates a Trust Record for every title and service document at the moment it's processed. Buyers receive an Asset Passport™ with verified history. You get protection if a record is ever challenged.

See it in 2 minutes: proofdeed.com/demo

Would a brief call make sense?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── Auto ISO / Quality Director — parts and safety documentation
  const auto_iso = `Hi ${first},

ISO/IATF audits require you to prove that safety and quality documentation is untampered — that the Certificate of Conformity your supplier submitted is the same one in your records today. When an audit or recall hits, that proof is what protects the organization.

ProofDeed creates a Trust Record for every quality and compliance document at the moment it's submitted — independently verifiable, legally defensible proof of integrity under FRE Rule 901. One API call alongside your existing QMS.

See it in 2 minutes: proofdeed.com/demo

Worth 20 minutes?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── County Recorder Anti-Fraud / Clouded Title
  const anti_fraud_recorder = `Hi ${first},

Deed fraud and clouded titles are becoming a significant operational burden for county recorders. Once a fraudulent deed is recorded, the damage to the chain of title — and the staff time to unwind it — is substantial.

ProofDeed creates a Trust Record for every deed at the moment of recording — a permanent digital fingerprint anchored to the Polygon blockchain. If that document is ever altered, the fingerprint doesn't match — immediate, irrefutable evidence of tampering. Legally defensible under FRE Rule 901.

No system replacement. Works alongside your existing recording software via a single API call.

See it in 2 minutes: proofdeed.com/demo

Worth a brief conversation this week?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
gov@proofdeed.com | proofdeed.com`;

  // ── Secretary of State / RON / e-Notarization
  const ron_director = `Hi ${first},

As states move toward Remote Online Notarization, the core challenge is proving document integrity after the fact — that what was notarized remotely is exactly what exists in the record today.

ProofDeed provides the cryptographic proof layer that RON is missing: a Trust Record created at the moment of notarization, independently verifiable by any party, legally defensible under FRE Rule 901.

We're currently working with state-level offices exploring how to make RON records defensible long-term.

Would a brief call make sense?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
gov@proofdeed.com | proofdeed.com`;

  // ── ALTA / Title Associations / Underwriters
  const alta_title = `Hi ${first},

Title fraud claims are expensive — and most of them come down to a document that can't be proven original. A deed that may have been altered. A release that doesn't match the recorded version. When the claim hits, the title company pays if they can't prove integrity.

ProofDeed creates a Trust Record for every title document at the moment it's processed — permanent, tamper-proof proof of the exact document at the exact time. Every claim that hinges on document integrity becomes immediately resolvable.

This reduces your fraud claim exposure directly.

See it in 2 minutes: proofdeed.com/demo

Worth 20 minutes?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── Attorney General / Fraud Unit
  const ag_fraud = `Hi ${first},

Home title theft and deed fraud cases are increasingly difficult to prosecute because the fraudulent document, by the time it's discovered, has passed through multiple hands. Proving which version was recorded and when — without an immutable record — often comes down to competing paper trails.

ProofDeed creates a Trust Record for every document at recording — a cryptographic fingerprint anchored to the Polygon blockchain. Legally defensible proof of integrity and timestamp under FRE Rule 901. It turns deed fraud into a provable, prosecutable offense.

Would a brief conversation make sense?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
gov@proofdeed.com | proofdeed.com`;

  // ── Tax Assessor — ownership data accuracy
  const tax_assessor = `Hi ${first},

Incorrect ownership data in assessment records often traces back to a title transfer that wasn't properly documented — or a deed where the recorded version doesn't match what was actually signed. The assessor's office bears the burden of reconciling disputes they didn't create.

ProofDeed creates a Trust Record for every deed and title document at the moment of recording — a permanent, tamper-proof anchor that makes ownership disputes immediately resolvable. No system replacement — single API call alongside your existing workflow.

See it in 2 minutes: proofdeed.com/demo

Worth a quick call?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
gov@proofdeed.com | proofdeed.com`;

  // ── Real Estate / PropTech — transaction document fraud, deed/agreement tampering
  const real_estate = `Hi ${first},

Property transaction fraud is surging. Forged deeds, altered purchase agreements, and backdated lease amendments are being used to challenge title, dispute valuations, and manufacture claims in commercial and residential disputes. When a document's authenticity is challenged in court, the producing party has to prove it wasn't altered — without a chain of custody that starts at creation, that defense is expensive and uncertain.

ProofDeed creates a Trust Record for every executed agreement, deed, or closing document at the moment it is processed — permanent proof of exactly what was in the document and when. Independently verifiable by any court without access to your systems. Legally defensible under FRE Rule 901. No process change for agents or attorneys.

No system replacement. Works alongside your existing DMS.

See it in 2 minutes: proofdeed.com/demo

Worth a 20-minute call?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── University / Research — research integrity, data fabrication, retraction risk
  const university_research = `Hi ${first},

Research data fabrication and document tampering are behind the majority of high-profile retractions — and increasingly the target of federal investigation. IRB files, lab notebooks, clinical datasets, and grant applications can all be altered after the fact, with no independent record of what was originally submitted. When misconduct is alleged, the institution carries the burden of proof.

ProofDeed creates a Trust Record for research documents at the moment they are created or submitted — tamper-proof, independently verifiable proof of the original. Any auditor, federal agency, or institutional review board can verify the record's integrity without accessing your internal systems. Legally defensible under FRE Rule 901.

No workflow change required.

See it in 2 minutes: proofdeed.com/demo

Worth a 20-minute call with your research integrity or compliance office?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

  // ── Government Regulators / Enforcement — evidence integrity, audit documentation
  const gov_regulator = `Hi ${first},

Enforcement actions fail when evidence integrity is challenged. Investigation documents, audit records, and regulatory findings can be questioned for authenticity — costing agencies years of litigation and, in some cases, entire prosecutions. The question is not whether your records are accurate. It is whether you can prove they were not altered after the fact.

ProofDeed creates an independent Trust Record for every investigation file, audit report, and regulatory finding at the moment it is generated — verifiable by any court or oversight body globally without relying on your internal infrastructure. If the integrity of a record is ever challenged, the answer is immediate.

Single API integration. No system replacement.

See it in 2 minutes: proofdeed.com/demo

Worth a brief call with your records, digital evidence, or compliance team?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
gov@proofdeed.com | proofdeed.com`;

  // ── Construction / Engineering — contract dispute documentation, claims evidence
  const construction_eng = `Hi ${first},

Construction disputes — change order fraud, backdated RFIs, altered scope-of-work documents — succeed because the producing party cannot prove what was in the document at the time it was issued. By the time arbitration or litigation begins, document integrity has been compromised and both sides are working from competing versions.

ProofDeed creates a Trust Record for every contract, RFI, change order, and progress report at the moment it is issued — establishing a permanent, immutable record of the original document. If authenticity is ever disputed, proof is immediate. Legally defensible under FRE Rule 901.

Single API integration alongside your existing document management system.

See it in 2 minutes: proofdeed.com/demo

Worth a 20-minute call?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;
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
    education:         credentialing,
    ip_timestamp:      ip_timestamp,
    blockchain_partner:  blockchain_partner,
    auto_oem:            auto_oem,
    intl_archives:       intl_archives,
    global_law_firm:     global_law_firm,
    global_insurance:    global_insurance,
    real_estate_ops:     real_estate,
    university_research: university_research,
    gov_regulator:       gov_regulator,
    construction_eng:    construction_eng,
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
    // Higher Ed / Healthcare
    inst_ciso:         inst_gcc,      // Third-party verifier angle resonates with CISOs
    inst_registrar:    inst_ir,       // Document integrity for diplomas/transcripts
    inst_him:          inst_gcc, // Third-party verifier angle for medical record integrity
    // PE / Institutional Trust-as-a-Service
    inst_coo:          inst_coo,
    inst_ir:           inst_ir,
    inst_gcc:          inst_gcc,
    inst_dd:           inst_dd,
    // Pharma / Life Sciences
    pharma_qa:         pharma_qa,
    pharma_cco:        pharma_cco,
    pharma_supply:     pharma_supply,
    pharma_clinical:   pharma_clinical,
    // Aviation / MRO
    aviation_dom:      aviation_dom,
    aviation_cto:      aviation_cto,
    aviation_parts:    aviation_parts,
    // Auto OEM / VIN integrity
    auto_supply:       auto_supply,
    auto_cdo:          auto_cdo,
    auto_remarketing:  auto_remarketing,
    auto_iso:          auto_iso,
    // Anti-fraud / Title Integrity
    anti_fraud:     anti_fraud_recorder,
    ron:            ron_director,
    alta:           alta_title,
    ag_fraud:       ag_fraud,
    tax:            tax_assessor,
    // Sandbox / Design Partner roles — routed through SANDBOX_EMAIL at send time;
    // these entries provide fallback text if called directly through INITIAL_EMAIL
    auto_remarketing2:      auto_remarketing,
    auto_warranty:          auto_iso,
    auto_dds:               auto_cdo,
    auto_coo:               auto_supply,
    auto_blockchain:        auto_cdo,
    inst_ethics:            inst_gcc,
    inst_fund:              inst_ir,
    inst_ma:                inst_dd,
    inst_aml:               inst_compliance,
    inst_digital_assets:    inst_gcc,
    pharma_gxp:             pharma_qa,
    pharma_trial:           pharma_clinical,
    pharma_serial:          pharma_supply,
    pharma_lims:            pharma_qa,
    pharma_coldchain:       pharma_supply,
    aviation_airworthy:     aviation_dom,
    aviation_logistics:     aviation_parts,
    aviation_cdo:           aviation_cto,
    aviation_sms:           aviation_dom,
    aviation_records:       aviation_parts,
    // UAE — routed through UAE_EMAIL at send time; these provide fallback text
    uae_redev:      recorder,
    uae_reops:      recorder,
    uae_legal:      inst_compliance,
    uae_recx:       recorder,
    uae_autodev:    auto_supply,
    // Shared fallbacks
    ops:            inst_compliance,
    finance:        inst_legal,
  };

  // Industry-based overrides — ensure the right template regardless of role assignment
  if (industry === 'healthcare') return inst_healthcare;
  if (industry === 'supply_chain') return supply_chain;
  if (industry === 'ip_research') return ip_timestamp;
  if (industry === 'insurance') return insurance_gen;
  if (industry === 'education') return credentialing;
  if (industry === 'blockchain_tech') return blockchain_partner;
  if (industry === 'auto_oem') return auto_oem;
  if (industry === 'pharma') return pharma_cco;
  if (industry === 'intl_archives') return intl_archives;
  if (industry === 'global_legal') return global_law_firm;
  if (industry === 'global_insurance') return global_insurance;
  if (industry === 'real_estate') return real_estate;
  if (industry === 'university_research') return university_research;
  if (industry === 'gov_regulator') return gov_regulator;
  if (industry === 'construction_detail') return construction_eng;

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
  if (['government','title_escrow','legal','auto','construction','pe_ma','pharma','aviation','uae_realestate','uae_auto'].includes(ind)) score += 3;

  // +2 Regulated industry
  if (['government','regulated','institutional','insurance','accounting','pharma','aviation','uae_realestate','uae_auto'].includes(ind)) score += 2;

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

// ── Google Custom Search lead finder (replaces Anthropic API) ──────────────
const EMAIL_REGEX = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
const SKIP_EMAIL_PATTERNS = /noreply|no-reply|donotreply|webmaster|postmaster|admin@|info@|support@|help@|contact@|office@|mail@|spam|abuse|privacy@|legal@|press@|compliance@|team@|hello@|general@|enquiries@|service@|ops@|operations@|claims@|hr@|billing@|accounts@|media@/i;

// Reject file-extension false-positives scraped from HTML (e.g. icon@2x.png, lib@1.0.min.js)
const FAKE_EMAIL_TLD = /\.(png|jpg|jpeg|gif|svg|webp|ico|js|mjs|cjs|css|min|map|woff|woff2|ttf|eot|otf|json|xml|zip|gz|pdf|doc|docx|xls|xlsx|txt|md|ts|jsx|tsx|vue|py|rb|php|sh|env|lock|yaml|yml|toml)(\?.*)?$/i;

// Strip HTML entities and artifacts before matching emails (e.g. > → >, &lt; → <)
function decodeHtmlEntities(str) {
  return str
    .replace(/\\u003e/gi, '').replace(/\\u003c/gi, '')
    .replace(/&gt;/gi, '').replace(/&lt;/gi, '')
    .replace(/&amp;/gi, '&').replace(/&#\d+;/g, '')
    .replace(/&[a-z]+;/gi, '');
}

function isLeadEmail(email) {
  if (SKIP_EMAIL_PATTERNS.test(email)) return false;
  if (email.length > 80) return false;
  // Reject HTML entity artifacts in the local part (e.g. u003eplease@domain.com)
  const local = email.split('@')[0] || '';
  if (/u003[ce]|u0026|u002[26]|&[a-z]+;|&#\d+;/i.test(local)) return false;
  // Local part must start with alphanumeric — not html remnants
  if (!/^[a-zA-Z0-9]/.test(local)) return false;
  // Local part must be at least 4 characters — blocks PDF binary garbage like m@, p@, u@
  if (local.length < 4) return false;
  // Must have a real TLD — reject file-extension lookalikes
  if (FAKE_EMAIL_TLD.test(email)) return false;
  // Must have at least one dot in the domain part
  const domain = email.split('@')[1] || '';
  if (!domain.includes('.')) return false;
  // Domain TLD must be 2–10 alpha chars (no digits-only TLDs like .2x)
  const tld = domain.split('.').pop();
  if (!/^[a-zA-Z]{2,10}$/.test(tld)) return false;
  // Domain must have a reasonable length (blocks 1-2 char domains like 1s.cf, k.ye)
  const domainWithoutTld = domain.substring(0, domain.lastIndexOf('.'));
  if (domainWithoutTld.length < 3) return false;
  // Block known placeholder/test domains
  const PLACEHOLDER_DOMAINS = /^(example|domain|test|sample|placeholder|email|user|company|yourcompany|yourdomain|mydomain|mycompany|acme|foo|bar|baz|lorem|ipsum|pagelines)\.com$/i;
  if (PLACEHOLDER_DOMAINS.test(domain)) return false;
  // Block role/generic local parts not caught by SKIP_EMAIL_PATTERNS
  const GENERIC_LOCAL = /^(sales|marketing|billing|accounts|hr|jobs|careers|media|news|editor|editors|editorial|subscribe|subscription|newsletter|hello|hello|team|general|enquiries|enquiry|request|requests|info2|office2|recruiter)$/i;
  if (GENERIC_LOCAL.test(local)) return false;
  return true;
}

function extractNameFromContext(html, email) {
  const idx = html.indexOf(email);
  if (idx === -1) return null;
  const ctx = html.substring(Math.max(0, idx - 300), idx + 100);
  // Common patterns: "Name: Jane Smith", "Jane Smith,", "Contact Jane Smith"
  const patterns = [
    /(?:name|contact|director|manager|recorder|clerk|officer)[:\s]+([A-Z][a-z]+ [A-Z][a-z]+)/i,
    /([A-Z][a-z]+ [A-Z][a-z]+)[\s,]+(?:director|manager|recorder|clerk|officer|attorney|coordinator)/i,
    /([A-Z][a-z]+ (?:[A-Z]\. )?[A-Z][a-z]+)/,
  ];
  for (const p of patterns) {
    const m = ctx.match(p);
    if (m && m[1] && m[1].length < 50) return m[1].trim();
  }
  return null;
}

function domainToCompany(domain) {
  // danecounty.gov → Dane County | cityofmadison.com → City of Madison
  const d = domain.replace(/^www\./, '').replace(/\.(gov|com|org|us|net).*$/, '');
  return d.replace(/([a-z])([A-Z])/g, '$1 $2')
          .replace(/[-_]/g, ' ')
          .replace(/\b\w/g, c => c.toUpperCase());
}

// US states rotated per-run so the same query targets a different geography each time,
// producing fresh results instead of the same top-10 pages already in the DB.
const US_STATES = [
  'Alabama','Alaska','Arizona','Arkansas','California','Colorado','Connecticut',
  'Delaware','Florida','Georgia','Hawaii','Idaho','Illinois','Indiana','Iowa',
  'Kansas','Kentucky','Louisiana','Maine','Maryland','Massachusetts','Michigan',
  'Minnesota','Mississippi','Missouri','Montana','Nebraska','Nevada',
  'New Hampshire','New Jersey','New Mexico','New York','North Carolina',
  'North Dakota','Ohio','Oklahoma','Oregon','Pennsylvania','Rhode Island',
  'South Carolina','South Dakota','Tennessee','Texas','Utah','Vermont',
  'Virginia','Washington','West Virginia','Wisconsin','Wyoming',
];

// Pick a state based on day-of-year + a per-target offset so different targets
// don't all hit the same state on the same day.
function pickState(targetIndex = 0) {
  const dayOfYear = Math.floor((Date.now() - new Date(new Date().getFullYear(), 0, 0)) / 86400000);
  return US_STATES[(dayOfYear + targetIndex) % US_STATES.length];
}

// Queries that already contain a specific state/city/country shouldn't get a second one appended.
function queryNeedsGeo(query) {
  const q = query.toLowerCase();
  // Skip if query already has a US state name, country, or geo-specific site: operator
  if (US_STATES.some(s => q.includes(s.toLowerCase()))) return false;
  if (/\bsite:\S+\.(gov|us)\b/.test(q)) return false; // gov site searches are already geo-specific
  if (/\b(uae|dubai|canada|uk|australia|india|global|international)\b/.test(q)) return false;
  return true;
}

async function searchLeadsViaGoogle(target, targetIndex = 0) {
  const apiKey = process.env.SERPER_API_KEY;
  if (!apiKey) {
    console.log('[LeadEngine] Missing SERPER_API_KEY — skipping');
    return [];
  }

  const leads = [];
  const seenEmails = new Set();

  // Append a rotating state to non-geo-specific queries to get fresh results each cycle
  const geoSuffix = queryNeedsGeo(target.query) ? ` ${pickState(targetIndex)}` : '';
  const query = target.query + geoSuffix;
  if (geoSuffix) console.log(`[LeadEngine] Geo-rotated query: "${query}"`);

  try {
    // 2 pages of Serper results = up to 20 URLs to mine
    for (let page = 1; page <= 2; page++) {
      const res = await fetch('https://google.serper.dev/search', {
        method: 'POST',
        headers: { 'X-API-KEY': apiKey, 'Content-Type': 'application/json' },
        body: JSON.stringify({ q: query, num: 10, page }),
      });
      if (!res.ok) { console.log(`[LeadEngine] Serper API error ${res.status}`); break; }
      const data = await res.json();
      const items = data.organic || [];
      if (!items.length) break;
      // Map Serper format to same structure as Google CSE
      const mappedItems = items.map(item => ({
        title: item.title || '',
        snippet: item.snippet || '',
        link: item.link || '',
        displayLink: item.link ? new URL(item.link).hostname : '',
      }));

      for (const item of mappedItems) {
        const domain = item.displayLink || '';

        // Skip PDF results entirely — scraping PDFs produces binary garbage that fakes email patterns
        const isPdf = /\.pdf(\?.*)?$/i.test(item.link) || /^\[PDF\]/i.test(item.title || '');
        if (isPdf) continue;

        const rawCompany = item.title
          ? item.title.split(/[-|–,]/)[0].trim()
          : domainToCompany(domain);
        // Skip if company name looks like garbage (starts with bracket, all caps gibberish, very short)
        if (/^\[/.test(rawCompany) || rawCompany.length < 3) continue;
        const company = rawCompany;

        // ① Quick pass — emails visible in snippet
        const snippetEmails = (item.snippet || '').match(EMAIL_REGEX) || [];
        for (const email of snippetEmails) {
          if (!isLeadEmail(email) || seenEmails.has(email)) continue;
          seenEmails.add(email);
          const name = extractNameFromContext(item.snippet, email) || target.title;
          leads.push({ name, title: target.title, email, company, industry: target.industry, source: item.link });
        }

        // ② Scrape the actual page for emails not in snippet
        try {
          const pageRes = await fetch(item.link, {
            signal: AbortSignal.timeout(6000),
            headers: { 'User-Agent': 'Mozilla/5.0 (compatible; ProofDeed/1.0)' },
          });
          if (!pageRes.ok) continue;
          // Skip if server returns a PDF content type
          const contentType = pageRes.headers.get('content-type') || '';
          if (contentType.includes('pdf')) continue;
          const html = decodeHtmlEntities(await pageRes.text());
          const pageEmails = html.match(EMAIL_REGEX) || [];
          for (const email of pageEmails) {
            if (!isLeadEmail(email) || seenEmails.has(email)) continue;
            seenEmails.add(email);
            const name = extractNameFromContext(html, email) || target.title;
            leads.push({ name, title: target.title, email, company, industry: target.industry, source: item.link });
          }
        } catch { /* timeout / blocked — skip page */ }

        await new Promise(r => setTimeout(r, 800)); // polite delay between pages
      }

      await new Promise(r => setTimeout(r, 500));
    }
  } catch (err) {
    console.error('[LeadEngine] Google search error:', err.message);
  }

  console.log(`[LeadEngine] Google found ${leads.length} raw leads for "${target.title}"`);
  return leads;
}

// ── ClinicalTrials.gov — real pharma PI/contact emails via public API ─────────
async function searchLeadsViaClinicalTrials(target) {
  const leads = [];
  const seenEmails = new Set();
  try {
    const query = encodeURIComponent(target.sponsor);
    const url = `https://clinicaltrials.gov/api/v2/studies?query.spons=${query}&pageSize=40`;
    const res = await fetch(url, {
      headers: { 'Accept': 'application/json' },
      signal: AbortSignal.timeout(12000),
    });
    if (!res.ok) { console.log(`[LeadEngine] ClinicalTrials API ${res.status}`); return []; }
    const data = await res.json();
    const studies = data.studies || [];
    for (const study of studies) {
      const mod = study.protocolSection?.contactsLocationsModule || {};
      const contacts = [
        ...(mod.centralContacts || []),
        ...(mod.overallOfficials || []),
      ];
      for (const c of contacts) {
        const email = c.centralContactEMail || c.overallOfficialEMail || null;
        const name  = c.centralContactName  || c.officialName || target.title;
        if (!email || !isLeadEmail(email) || seenEmails.has(email)) continue;
        seenEmails.add(email);
        leads.push({ name, title: target.title, email, company: target.company, industry: target.industry, source: 'https://clinicaltrials.gov' });
      }
    }
  } catch (err) {
    console.error('[LeadEngine] ClinicalTrials error:', err.message);
  }
  console.log(`[LeadEngine] ClinicalTrials found ${leads.length} leads for "${target.title}"`);
  return leads;
}

// ── PubMed/NCBI — corresponding author emails from research papers ────────────
async function searchLeadsViaPubMed(target) {
  const leads = [];
  const seenEmails = new Set();
  try {
    // Step 1: search for PMIDs
    const searchRes = await fetch(
      `https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi?db=pubmed&term=${encodeURIComponent(target.pubmedQuery)}&retmax=20&retmode=json`,
      { signal: AbortSignal.timeout(10000) }
    );
    if (!searchRes.ok) return [];
    const searchData = await searchRes.json();
    const pmids = searchData.esearchresult?.idlist || [];
    if (!pmids.length) return [];

    // Step 2: fetch abstracts which often contain author emails
    const fetchRes = await fetch(
      `https://eutils.ncbi.nlm.nih.gov/entrez/eutils/efetch.fcgi?db=pubmed&id=${pmids.join(',')}&retmode=text&rettype=abstract`,
      { signal: AbortSignal.timeout(12000) }
    );
    if (!fetchRes.ok) return [];
    const text = decodeHtmlEntities(await fetchRes.text());
    const emails = text.match(EMAIL_REGEX) || [];
    for (const email of emails) {
      if (!isLeadEmail(email) || seenEmails.has(email)) continue;
      seenEmails.add(email);
      const name = extractNameFromContext(text, email) || target.title;
      leads.push({ name, title: target.title, email, company: target.company, industry: target.industry, source: 'https://pubmed.ncbi.nlm.nih.gov' });
    }
  } catch (err) {
    console.error('[LeadEngine] PubMed error:', err.message);
  }
  console.log(`[LeadEngine] PubMed found ${leads.length} leads for "${target.title}"`);
  return leads;
}
// ─────────────────────────────────────────────────────────────────────────────
// Internal email scoring system — no third-party APIs
// Scores every email 0–100 before send. Minimum score to send: 45.
// Domain reputation tracked in DB and updated on every bounce/deliver event.

const _dnsCache = new Map(); // domain → { mx, spf, dmarc, ts }
const DNS_CACHE_TTL = 6 * 3600 * 1000; // 6 hours

const BLOCKED_PREFIXES = new Set([
  'noreply','no-reply','no_reply','donotreply','do-not-reply','do_not_reply',
  'bounce','bounces','mailer-daemon','postmaster','abuse','spam','junk',
  'unsubscribe','webmaster','root','lossrun','loss-run','claimsnotice',
  'paperworkreductionact','notifications','notification','alerts','alert',
  'automated','auto','automailer','newsletter','news','press','media',
  'accounts','accountsreceivable','accountspayable','invoices','billing',
  'jobs','careers','recruiting','humanresources','hr','helpdesk','support',
  'info','contact','hello','hi','team','office','general','admin','administrator',
  'enquiries','enquiry','mail','email','listserv','listserve','mailbox',
  'feedback','reply','replies','donotrespond','do-not-respond',
  'customerservice','customer-service','service','sales','marketing',
  'webmaster','hostmaster','dmarc','security','privacy','legal',
  'training','education','test','testing','demo','sandbox',
]);

const BLOCKED_EXACT = new Set([
  'paperworkreductionact@sec.gov','license@tdi.texas.gov',
]);

// Patterns that suggest a real person (firstname.lastname or firstinitial.lastname)
const PERSONAL_PATTERN = /^[a-z]{2,}[._-][a-z]{2,}(\d{0,3})?$/;
const FIRSTNAME_ONLY = /^[a-z]{3,12}(\d{0,2})?$/;

async function getDnsInfo(domain) {
  const cached = _dnsCache.get(domain);
  if (cached && (Date.now() - cached.ts) < DNS_CACHE_TTL) return cached;

  const { promises: dns } = await import('dns');
  const result = { mx: false, spf: false, dmarc: false, ts: Date.now() };

  await Promise.allSettled([
    Promise.race([dns.resolveMx(domain), new Promise((_, r) => setTimeout(() => r(new Error('timeout')), 4000))])
      .then(mx => { result.mx = Array.isArray(mx) && mx.length > 0; }).catch(() => {}),
    Promise.race([dns.resolveTxt(domain), new Promise((_, r) => setTimeout(() => r(new Error('timeout')), 4000))])
      .then(txt => { result.spf = txt.flat().some(r => r.startsWith('v=spf1')); }).catch(() => {}),
    Promise.race([dns.resolveTxt(`_dmarc.${domain}`), new Promise((_, r) => setTimeout(() => r(new Error('timeout')), 4000))])
      .then(txt => { result.dmarc = txt.flat().some(r => r.startsWith('v=DMARC1')); }).catch(() => {}),
  ]);

  _dnsCache.set(domain, result);
  return result;
}

async function getDomainReputation(domain) {
  try {
    const row = await pool.query(
      `SELECT bounce_count, deliver_count, is_catch_all, suppressed FROM domain_reputation WHERE domain=$1`,
      [domain]
    );
    return row.rows[0] || null;
  } catch { return null; }
}

async function scoreEmail(email) {
  if (!email || typeof email !== 'string') return { score: 0, reason: 'invalid_format' };
  const clean = email.toLowerCase().trim();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(clean)) return { score: 0, reason: 'invalid_format' };

  const atIdx = clean.lastIndexOf('@');
  const local = clean.slice(0, atIdx);
  const domain = clean.slice(atIdx + 1);

  if (BLOCKED_EXACT.has(clean)) return { score: 0, reason: 'blocked_exact' };

  // Check blocked prefixes — exact match or starts-with for compound prefixes
  const localBase = local.split(/[._+]/)[0];
  if (BLOCKED_PREFIXES.has(local) || BLOCKED_PREFIXES.has(localBase)) return { score: 0, reason: 'role_address' };

  // Check domain reputation from DB
  const rep = await getDomainReputation(domain);
  if (rep?.suppressed) return { score: 0, reason: 'domain_suppressed' };
  if (rep) {
    const total = (rep.bounce_count || 0) + (rep.deliver_count || 0);
    if (total >= 5) {
      const bounceRate = rep.bounce_count / total;
      if (bounceRate >= 0.5) return { score: 0, reason: 'domain_high_bounce' };
    }
  }

  // DNS checks
  const dns = await getDnsInfo(domain);
  if (!dns.mx) return { score: 0, reason: 'no_mx' };

  let score = 30; // base for passing MX

  // DNS quality signals
  if (dns.spf) score += 15;
  if (dns.dmarc) score += 10;

  // Domain type bonuses
  const tld = domain.split('.').pop();
  if (domain.endsWith('.gov') || domain.endsWith('.mil')) score += 25;
  else if (domain.endsWith('.edu')) score += 15;
  else if (domain.endsWith('.org')) score += 5;
  else if (['com','net','biz'].includes(tld)) score += 0;

  // Catch-all penalty — domain delivers everything but most inboxes don't exist
  if (rep?.is_catch_all) score -= 20;

  // Email format scoring
  if (PERSONAL_PATTERN.test(local)) score += 15; // firstname.lastname
  else if (FIRSTNAME_ONLY.test(local)) score += 5;
  else if (/\d{3,}/.test(local)) score -= 10; // lots of numbers = auto-generated
  else if (local.length > 30) score -= 10; // suspiciously long

  // Penalize if domain has prior bounces (but not suppressed)
  if (rep) {
    const total = (rep.bounce_count || 0) + (rep.deliver_count || 0);
    if (total >= 3) {
      const bounceRate = rep.bounce_count / total;
      if (bounceRate >= 0.3) score -= 15;
      else if (bounceRate >= 0.15) score -= 5;
    }
  }

  score = Math.max(0, Math.min(100, score));
  return { score, reason: score >= 45 ? 'ok' : 'low_score', is_catch_all: rep?.is_catch_all || false };
}

// Backward-compat wrapper used by existing send logic
async function isEmailDeliverable(email) {
  const { score, reason } = await scoreEmail(email);
  if (score < 45) console.log(`[EmailScore] Skip ${email} — score ${score} (${reason})`);
  return score >= 45;
}

// Called by bounce webhook to keep domain_reputation current
async function recordEmailEvent(email, event) {
  try {
    const domain = email.toLowerCase().split('@')[1];
    if (!domain) return;
    if (event === 'bounce') {
      await pool.query(`
        INSERT INTO domain_reputation (domain, bounce_count, deliver_count, last_seen)
        VALUES ($1, 1, 0, NOW())
        ON CONFLICT (domain) DO UPDATE SET
          bounce_count = domain_reputation.bounce_count + 1,
          last_seen = NOW()
      `, [domain]);
      // Suppress if: 2+ bounces with zero delivers, OR 4+ total with 40%+ bounce rate
      const row = await pool.query(`SELECT bounce_count, deliver_count FROM domain_reputation WHERE domain=$1`, [domain]);
      if (row.rows[0]) {
        const { bounce_count, deliver_count } = row.rows[0];
        const total = bounce_count + deliver_count;
        const shouldSuppress = (bounce_count >= 2 && deliver_count === 0) ||
                               (total >= 4 && bounce_count / total >= 0.4);
        if (shouldSuppress) {
          await pool.query(`UPDATE domain_reputation SET suppressed=true WHERE domain=$1`, [domain]);
          console.log(`[DomainRep] Suppressed domain ${domain} — ${bounce_count}/${total} bounced`);
        }
      }
    } else if (event === 'deliver') {
      await pool.query(`
        INSERT INTO domain_reputation (domain, bounce_count, deliver_count, last_seen)
        VALUES ($1, 0, 1, NOW())
        ON CONFLICT (domain) DO UPDATE SET
          deliver_count = domain_reputation.deliver_count + 1,
          last_seen = NOW()
      `, [domain]);
    } else if (event === 'catch_all') {
      await pool.query(`
        INSERT INTO domain_reputation (domain, bounce_count, deliver_count, is_catch_all, last_seen)
        VALUES ($1, 0, 0, true, NOW())
        ON CONFLICT (domain) DO UPDATE SET is_catch_all=true, last_seen=NOW()
      `, [domain]);
    }
  } catch (err) {
    console.error('[DomainRep] recordEmailEvent error:', err.message);
  }
}

async function runLeadEngine(targetsPerRun = 3) {
  if (!process.env.SERPER_API_KEY || !process.env.RESEND_API_KEY) {
    console.log(`[LeadEngine] Missing API keys — SERPER: ${!!process.env.SERPER_API_KEY}, RESEND: ${!!process.env.RESEND_API_KEY}`);
    return;
  }

  // Prevent overlapping runs — but auto-reset if stuck for more than 3 hours
  const runningRow = await pool.query(`SELECT value, updated_at FROM lead_engine_state WHERE key='is_running'`).catch(() => ({ rows: [] }));
  if (runningRow.rows[0]?.value === 'true') {
    const stuckSince = runningRow.rows[0]?.updated_at;
    const stuckHours = stuckSince ? (Date.now() - new Date(stuckSince).getTime()) / 3600000 : 0;
    if (stuckHours < 3) {
      console.log('[LeadEngine] Already running — skipping duplicate trigger.');
      return;
    }
    console.log(`[LeadEngine] is_running stuck for ${stuckHours.toFixed(1)}h — auto-resetting.`);
    await pool.query(`INSERT INTO lead_engine_state (key,value,updated_at) VALUES ('is_running','false',NOW()) ON CONFLICT (key) DO UPDATE SET value='false',updated_at=NOW()`).catch(() => {});
  }

  // Mark as running
  await pool.query(
    `INSERT INTO lead_engine_state (key, value, updated_at) VALUES ('is_running','true',NOW())
     ON CONFLICT (key) DO UPDATE SET value='true', updated_at=NOW()`
  ).catch(() => {});

  const TARGETS_PER_RUN = targetsPerRun;
  const ALL_TARGETS = [...LEAD_TARGETS, ...AFFILIATE_TARGETS];

  // Get current rotation index
  const idxRow = await pool.query(`SELECT value FROM lead_engine_state WHERE key='rotation_index'`).catch(() => ({ rows: [] }));
  const currentIdx = idxRow.rows[0] ? parseInt(idxRow.rows[0].value) : 0;
  const nextIdx = (currentIdx + TARGETS_PER_RUN) % ALL_TARGETS.length;

  console.log(`[LeadEngine] Starting — ${TARGETS_PER_RUN} targets from index ${currentIdx}, next will be ${nextIdx}`);

  // Save next index immediately so crashes don't repeat the same targets
  await pool.query(
    `INSERT INTO lead_engine_state (key, value, updated_at) VALUES ('rotation_index',$1,NOW())
     ON CONFLICT (key) DO UPDATE SET value=$1, updated_at=NOW()`,
    [String(nextIdx)]
  ).catch(() => {});

  const { Resend } = await import('resend');
  const resend = new Resend(process.env.RESEND_API_KEY);

  // Hard daily send cap — 50,000/month Resend paid tier ÷ 30 days
  const DAILY_SEND_CAP = 1667;
  const todayStart = new Date(); todayStart.setHours(0,0,0,0);
  const sentTodayRow = await pool.query(
    `SELECT COUNT(*) FROM outreach_contacts WHERE first_sent_at >= $1`,
    [todayStart]
  ).catch(() => ({ rows: [{ count: '0' }] }));
  let dailySentSoFar = parseInt(sentTodayRow.rows[0]?.count || '0');

  let totalSent = 0, totalSkipped = 0;

  if (dailySentSoFar >= DAILY_SEND_CAP) {
    console.log(`[LeadEngine] Daily cap reached (${dailySentSoFar}/${DAILY_SEND_CAP}) — skipping run.`);
    await pool.query(`INSERT INTO lead_engine_state (key,value,updated_at) VALUES ('is_running','false',NOW()) ON CONFLICT (key) DO UPDATE SET value='false',updated_at=NOW()`).catch(() => {});
    return;
  }

  // Process targets sequentially (not parallel) to keep daily cap accurate
  const PARALLEL = 1;
  for (let batch = 0; batch < TARGETS_PER_RUN; batch += PARALLEL) {
    const batchTargets = Array.from({ length: Math.min(PARALLEL, TARGETS_PER_RUN - batch) }, (_, j) =>
      ({ target: ALL_TARGETS[(currentIdx + batch + j) % ALL_TARGETS.length], idx: batch + j })
    );
    console.log(`[LeadEngine] Batch ${Math.floor(batch/PARALLEL)+1} — ${batchTargets.map(b => b.target.title).join(', ')}`);

    const batchResults = await Promise.allSettled(batchTargets.map(async ({ target, idx }) => {
      try {
        const leads = target.source === 'clinicaltrials'
          ? await searchLeadsViaClinicalTrials(target)
          : target.source === 'pubmed'
            ? await searchLeadsViaPubMed(target)
            : await searchLeadsViaGoogle(target, currentIdx + idx);
        if (!leads.length) {
          console.log(`[LeadEngine] No leads found for ${target.title}`);
          return { sent: 0, skipped: 0 };
        }

        let sent = 0, skipped = 0;
        for (const lead of leads) {
          if (dailySentSoFar + totalSent >= DAILY_SEND_CAP) { skipped++; continue; } // daily cap guard
          if (!lead.email || !lead.name || !lead.company) { skipped++; continue; }
          const deliverable = await isEmailDeliverable(lead.email);
          if (!deliverable) { skipped++; console.log(`[LeadEngine] Skipped (undeliverable): ${lead.email}`); continue; }
          const exists = await pool.query('SELECT id, pipeline_stage FROM outreach_contacts WHERE email=$1', [lead.email.toLowerCase()]);
          if (exists.rows.length > 0) { skipped++; continue; } // already contacted or suppressed

          const replyTag = crypto.randomBytes(8).toString('hex');
          const isAffiliate = target.tier === 'affiliate';
          const isUAE = ['uae_realestate','uae_auto'].includes(target.industry);
          const sandboxRoles = new Set(['auto_remarketing2','auto_warranty','auto_dds','auto_coo','auto_blockchain','inst_ethics','inst_fund','inst_ma','inst_aml','inst_digital_assets','pharma_gxp','pharma_trial','pharma_serial','pharma_lims','pharma_coldchain','aviation_airworthy','aviation_logistics','aviation_cdo','aviation_sms','aviation_records']);
          const isSandbox = sandboxRoles.has(target.role);
          const emailBody = isAffiliate
            ? AFFILIATE_EMAIL(lead.name, lead.company, target.role)
            : isUAE
              ? UAE_EMAIL(lead.name, lead.company, target.role)
              : isSandbox
                ? SANDBOX_EMAIL(lead.name, lead.company, target.role)
                : INITIAL_EMAIL(lead.name, lead.company, lead.industry || target.industry, target.role);
          const subject = isAffiliate
            ? `Revenue share idea for ${lead.company}`
            : isUAE
              ? `${lead.company} — Dubai 2026 paperless mandate`
              : isSandbox
                ? `Document integrity pilot — ${lead.company}`
                : `Quick question for ${lead.company}`;

          try {
            const fromAddr = target.industry === 'government'
              ? 'Scott Kiersten <gov@proofdeed.com>'
              : 'Scott Kiersten <info@proofdeed.com>';
            const emailHtml = `<div style="font-family:sans-serif;font-size:15px;line-height:1.6;color:#222;max-width:600px">${emailBody.replace(/\n\n/g,'</p><p>').replace(/\n/g,'<br>')}</div>`;
            const result = await resend.emails.send({
              from: fromAddr,
              reply_to: fromAddr,
              to: lead.email,
              subject,
              text: emailBody,
              html: emailHtml,
            });

            const pscore = calcPriorityScore(lead.title, lead.industry || target.industry, target.role);
            const useCase = `${target.title} — ${(lead.industry || target.industry).replace(/_/g,' ')}`;
            await pool.query(
              `INSERT INTO outreach_contacts (name, email, company, title, industry, tier, priority_score, pipeline_stage, pain_status, use_case, status, reply_to_tag, resend_message_id, requires_human, first_sent_at, last_contact_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,'contacted','unaware',$8,'sent',$9,$10,FALSE,NOW(),NOW())`,
              [lead.name, lead.email.toLowerCase(), lead.company, lead.title, lead.industry || target.industry, target.tier || 'primary', pscore, useCase, replyTag, result.data?.id || null]
            );
            await pool.query(
              `INSERT INTO outreach_events (contact_id, event_type, event_source, metadata, occurred_at)
               SELECT id, 'sent', 'lead_engine', $1, NOW() FROM outreach_contacts WHERE email=$2`,
              [JSON.stringify({ subject, source: lead.source }), lead.email.toLowerCase()]
            );

            sent++;
            console.log(`[LeadEngine] Sent → ${lead.name} (${lead.company})`);
            await new Promise(r => setTimeout(r, 2000));
          } catch (e) {
            console.error(`[LeadEngine] Send fail ${lead.email}:`, e.message);
            skipped++;
          }
        }
        console.log(`[LeadEngine] Target done — sent: ${sent}, skipped: ${skipped}`);
        return { sent, skipped };
      } catch (err) {
        console.error(`[LeadEngine] Error on target ${target.title}:`, err.message);
        return { sent: 0, skipped: 0 };
      }
    }));

    for (const r of batchResults) {
      if (r.status === 'fulfilled') {
        totalSent += r.value.sent;
        totalSkipped += r.value.skipped;
      }
    }
  }

  await pool.query(
    `INSERT INTO lead_engine_state (key, value, updated_at) VALUES ('last_run',$1,NOW())
     ON CONFLICT (key) DO UPDATE SET value=$1, updated_at=NOW()`,
    [new Date().toISOString()]
  );
  await pool.query(
    `INSERT INTO lead_engine_state (key, value, updated_at) VALUES ('last_result',$1,NOW())
     ON CONFLICT (key) DO UPDATE SET value=$1, updated_at=NOW()`,
    [JSON.stringify({ targets: TARGETS_PER_RUN, sent: totalSent, skipped: totalSkipped })]
  );

  console.log(`[LeadEngine] All done. Total sent: ${totalSent}, skipped: ${totalSkipped}, next index: ${nextIdx}`);

  // Mark as no longer running
  await pool.query(
    `INSERT INTO lead_engine_state (key, value, updated_at) VALUES ('is_running','false',NOW())
     ON CONFLICT (key) DO UPDATE SET value='false', updated_at=NOW()`
  ).catch(() => {});
}

// Lead engine — 7 days/week, twice daily at 8am and 2pm Chicago, 200 targets per run
cron.schedule('0 8 * * *', () => runLeadEngine(200), { timezone: 'America/Chicago' });
cron.schedule('0 14 * * *', () => runLeadEngine(200), { timezone: 'America/Chicago' });

/* ---------------- Lead Engine API ----------------  */
app.get(['/api/admin/lead-engine', '/admin/lead-engine'], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: 'Unauthorized.' });
  try {
    const rows = await pool.query('SELECT key, value, updated_at FROM lead_engine_state').catch(() => ({ rows: [] }));
    const state = {};
    rows.rows.forEach(r => { state[r.key] = { value: r.value, updated_at: r.updated_at }; });
    res.json({
      enabled: true,
      is_running: state.is_running?.value === 'true',
      targets: LEAD_TARGETS.map((t, i) => ({ ...t, index: i })),
      currentIndex: parseInt(state.rotation_index?.value || '0'),
      lastRun: state.last_run?.value || null,
      lastResult: state.last_result?.value ? JSON.parse(state.last_result.value) : null,
      nextTarget: LEAD_TARGETS[parseInt(state.rotation_index?.value || '0') % LEAD_TARGETS.length],
      schedule: 'Tue/Wed/Thu 8am PT',
      envCheck: {
        SERPER_API_KEY: !!process.env.SERPER_API_KEY,
        RESEND_API_KEY: !!process.env.RESEND_API_KEY,
      },
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post(['/api/admin/lead-engine/run', '/admin/lead-engine/run'], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: 'Unauthorized.' });

  // Check if already running
  const runningRow = await pool.query(`SELECT value FROM lead_engine_state WHERE key='is_running'`).catch(() => ({ rows: [] }));
  if (runningRow.rows[0]?.value === 'true') {
    return res.json({ success: false, message: 'Engine is already running — check DO logs for progress.' });
  }

  const count = parseInt(req.body?.count) || 3;
  res.json({ success: true, running: true, message: `Lead engine started — ${count} targets. Refresh in 2-3 minutes.` });
  runLeadEngine(count).catch(err => {
    console.error('[LeadEngine] Fatal error:', err.message);
    // Always clear the running flag even if it crashes
    pool.query(`INSERT INTO lead_engine_state (key,value,updated_at) VALUES ('is_running','false',NOW()) ON CONFLICT (key) DO UPDATE SET value='false',updated_at=NOW()`).catch(() => {});
  });
});

// Force-reset stuck is_running flag
app.post(['/api/admin/lead-engine/reset', '/admin/lead-engine/reset'], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: 'Unauthorized.' });
  await pool.query(`INSERT INTO lead_engine_state (key,value,updated_at) VALUES ('is_running','false',NOW()) ON CONFLICT (key) DO UPDATE SET value='false',updated_at=NOW()`).catch(() => {});
  res.json({ success: true, message: 'Engine flag reset — you can now run again.' });
});

/* ---------------- Outreach Autopilot (daily 8am UTC) ---------------- */
async function sendOutreachFollowUp(contact, day) {
  if (!process.env.RESEND_API_KEY) return;
  // Skip generic "Team [Company]" contacts — no real person to follow up with
  if (/^team\b/i.test(contact.name.trim())) return;
  const { Resend } = await import('resend');
  const resend = new Resend(process.env.RESEND_API_KEY);
  const rawFirst = contact.name.split(' ')[0];
  const first = /^(team|unknown|contact|info|null)$/i.test(rawFirst) ? contact.company.split(' ')[0] : rawFirst;

  let text, subject;
  if (day === 7) {
    text = `Hi ${first},

Following up on my note from last week about proving record authenticity for ${contact.company}.

Document fraud is rising — altered contracts, disputed titles, falsified records. The organizations best protected are those that can prove what's real: that a record existed, was unaltered, and is exactly what they say it is.

ProofDeed creates permanent Trust Records that provide independently verifiable proof of authenticity, history, and ownership. No system replacement required — live via API in days.

See it in 2 minutes: proofdeed.com/demo

Would you have 20 minutes this week for a quick walkthrough?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;
    subject = `Re: Quick question for ${contact.company}`;
  } else if (day === 14) {
    text = `Hi ${first},

One more note on this — a simple question:

Can ${contact.company} prove that its most important records are authentic, unaltered, and exactly what you say they are?

If the answer isn't an immediate yes, that's the gap ProofDeed fills. We create permanent Trust Records — independently verifiable proof of authenticity, ownership, and history that holds up long after the original system changes.

Is this on your radar for this year, or is the timing simply not right?

Either answer helps. If it is relevant, I'd love 15 minutes to show you how it works.

proofdeed.com/demo

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;
    subject = `Re: Quick question for ${contact.company}`;
  } else {
    text = `Hi ${first},

I've reached out a couple of times about record authenticity and trust infrastructure for ${contact.company} — haven't heard back, so I'll assume the timing isn't right and close out my follow-ups.

If that changes, I'm easy to reach. ProofDeed helps organizations prove what's real — permanent, independently verifiable Trust Records for documents, assets, and ownership history. Legally defensible under FRE Rule 901. No system replacement required.

One last ask: if there's someone else at ${contact.company} better suited for this conversation, I'd appreciate a quick introduction.

Either way, appreciate your time.

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;
    subject = `Re: Quick question for ${contact.company}`;
  }

  const replyTag = crypto.randomBytes(8).toString('hex');
  const followUpFrom = (contact.industry === 'government' || contact.industry === 'gov_regulator')
    ? 'Scott Kiersten <gov@proofdeed.com>'
    : 'Scott Kiersten <info@proofdeed.com>';
  await resend.emails.send({
    from: followUpFrom,
    reply_to: followUpFrom,
    to: contact.email,
    subject,
    text,
  });

  await pool.query(
    `UPDATE outreach_contacts SET status='sent', last_contact_at=NOW(), reply_to_tag=$1, auto_replied=true WHERE id=$2`,
    [replyTag, contact.id]
  );
  await pool.query(
    `INSERT INTO outreach_events (contact_id, event_type, event_source, metadata, occurred_at)
     VALUES ($1, $2, 'autopilot', $3, NOW())`,
    [contact.id, day === 7 ? 'follow_up_1' : day === 14 ? 'follow_up_2' : 'breakup', JSON.stringify({ subject, day })]
  );
}

cron.schedule('0 8 * * *', async () => {
  console.log('[Autopilot] Running daily follow-up check...');
  try {
    // Global daily cap — Resend paid tier, no daily limit
    const AUTOPILOT_DAILY_CAP = 100; // max follow-ups per day
    const todayStart = new Date(); todayStart.setHours(0,0,0,0);
    const newSentToday = parseInt((await pool.query(
      `SELECT COUNT(*) FROM outreach_contacts WHERE first_sent_at >= $1`, [todayStart]
    ).catch(() => ({ rows: [{ count: '0' }] }))).rows[0]?.count || '0');
    const followUpsSentToday = parseInt((await pool.query(
      `SELECT COUNT(*) FROM outreach_events WHERE event_source='autopilot' AND occurred_at >= $1`, [todayStart]
    ).catch(() => ({ rows: [{ count: '0' }] }))).rows[0]?.count || '0');
    let autopilotSent = 0;
    const remainingBudget = Math.max(0, AUTOPILOT_DAILY_CAP - followUpsSentToday);
    console.log(`[Autopilot] Budget: ${remainingBudget} follow-ups remaining (${newSentToday} new sent today, ${followUpsSentToday} follow-ups already sent)`);
    if (remainingBudget === 0) {
      console.log('[Autopilot] Daily follow-up cap reached — skipping.');
      return;
    }

    // Base filter shared across all follow-up tiers
    const BASE_FILTER = `
      status NOT IN ('replied','in_talks','closed_won','closed_lost','bounced','complained','unsubscribed')
      AND pipeline_stage NOT IN ('pilot_discussed','pilot_sent','pilot_approved','closed','qualified','suppressed')
      AND auto_replied = false
      AND company NOT LIKE '[PDF]%'
      AND length(split_part(email, '@', 1)) > 3
    `;

    // Day 21 breakup first — highest priority, closes the loop
    // Window: 21+ days since first send, no follow-up yet
    const day21 = await pool.query(`
      SELECT * FROM outreach_contacts
      WHERE ${BASE_FILTER}
      AND first_sent_at <= NOW() - INTERVAL '21 days'
      AND first_sent_at > NOW() - INTERVAL '60 days'
      ORDER BY first_sent_at ASC
      LIMIT 30
    `);
    for (const c of day21.rows) {
      if (autopilotSent >= remainingBudget) break;
      try {
        await sendOutreachFollowUp(c, 21);
        autopilotSent++;
        await pool.query(`UPDATE outreach_contacts SET status='closed_lost', auto_replied=true WHERE id=$1`, [c.id]);
        console.log(`[Autopilot] Day 21 breakup → ${c.name}`);
      }
      catch (e) { console.error(`[Autopilot] Day 21 fail ${c.email}:`, e.message); }
      await new Promise(r => setTimeout(r, 2000));
    }

    // Day 14: second follow-up — 14–20 days since first send, no follow-up yet
    const day14 = await pool.query(`
      SELECT * FROM outreach_contacts
      WHERE ${BASE_FILTER}
      AND first_sent_at <= NOW() - INTERVAL '14 days'
      AND first_sent_at > NOW() - INTERVAL '21 days'
      ORDER BY first_sent_at ASC
      LIMIT 30
    `);
    for (const c of day14.rows) {
      if (autopilotSent >= remainingBudget) break;
      try { await sendOutreachFollowUp(c, 14); autopilotSent++; console.log(`[Autopilot] Day 14 → ${c.name}`); }
      catch (e) { console.error(`[Autopilot] Day 14 fail ${c.email}:`, e.message); }
      await new Promise(r => setTimeout(r, 2000));
    }

    // Day 7: first follow-up — 7–13 days since first send, no follow-up yet
    const day7 = await pool.query(`
      SELECT * FROM outreach_contacts
      WHERE ${BASE_FILTER}
      AND first_sent_at <= NOW() - INTERVAL '7 days'
      AND first_sent_at > NOW() - INTERVAL '14 days'
      ORDER BY first_sent_at ASC
      LIMIT 30
    `);
    for (const c of day7.rows) {
      if (autopilotSent >= remainingBudget) break;
      try { await sendOutreachFollowUp(c, 7); autopilotSent++; console.log(`[Autopilot] Day 7 → ${c.name}`); }
      catch (e) { console.error(`[Autopilot] Day 7 fail ${c.email}:`, e.message); }
      await new Promise(r => setTimeout(r, 2000));
    }

    console.log(`[Autopilot] Done. Sent: ${autopilotSent}. Day7 eligible: ${day7.rows.length}, Day14 eligible: ${day14.rows.length}, Day21 eligible: ${day21.rows.length}`);
  } catch (err) {
    console.error('[Autopilot] Cron error:', err.message);
  }
}, { timezone: 'America/Los_Angeles' });

/* ---------------- System Health Monitor ---------------- */
const ADMIN_ALERT_EMAIL = process.env.MAIL_TO || 'info@proofdeed.com';
let lastAlertSent = {};
let failureStreak = {};  // tracks consecutive failure count per service
const ALERT_AFTER_FAILURES = 3; // must fail 3 checks in a row (~45 min) before alerting

async function sendAlertEmail(subject, body) {
  if (!process.env.RESEND_API_KEY) {
    console.error('[HealthMonitor] RESEND_API_KEY not set — cannot send alert email');
    return;
  }
  try {
    const { Resend } = await import('resend');
    const resend = new Resend(process.env.RESEND_API_KEY);
    const result = await resend.emails.send({
      from: 'ProofDeed System <noreply@proofdeed.com>',
      to: ADMIN_ALERT_EMAIL,
      subject,
      text: body,
    });
    console.log(`[HealthMonitor] Alert email sent to ${ADMIN_ALERT_EMAIL}`, result?.data?.id || '');
  } catch (e) {
    console.error('[HealthMonitor] Failed to send alert email:', e.message);
  }
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

  // 2. Stripe API
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

  // 5. Key Site Pages (frontend)
  const pagesToCheck = ['/', '/government', '/login', '/verify', '/how-it-works', '/api-docs'];
  for (const page of pagesToCheck) {
    try {
      const r = await fetch(`https://proofdeed.com${page}`, { signal: AbortSignal.timeout(10000) });
      checks.push({ name: `Page ${page}`, ok: r.status === 200, error: r.status !== 200 ? `HTTP ${r.status}` : null });
    } catch (e) {
      checks.push({ name: `Page ${page}`, ok: false, error: e.message });
    }
  }

  // 6. All Checkout Plans (creates real Stripe sessions — no charge until customer pays)
  const checkoutPlans = [
    { name: 'Checkout starter-monthly', mode: 'subscription', price: process.env.PRICE_STARTER_MONTHLY },
    { name: 'Checkout starter-annual',  mode: 'subscription', price: process.env.PRICE_STARTER_YEARLY },
    { name: 'Checkout pro-monthly',     mode: 'subscription', price: process.env.PRICE_PRO_MONTHLY },
    { name: 'Checkout pro-annual',      mode: 'subscription', price: process.env.PRICE_PRO_YEARLY },
    { name: 'Checkout enterprise',      mode: 'subscription', price: process.env.PRICE_ENTERPRISE },
    { name: 'Checkout government-pilot',mode: 'payment',      price: process.env.PRICE_GOVERNMENT_PILOT },
  ];
  for (const plan of checkoutPlans) {
    try {
      const session = await stripe.checkout.sessions.create({
        mode: plan.mode,
        ...(plan.mode === 'subscription' ? { payment_method_types: ['card'] } : {}),
        line_items: [{ price: plan.price, quantity: 1 }],
        success_url: 'https://proofdeed.com/success',
        cancel_url: 'https://proofdeed.com',
      });
      checks.push({ name: plan.name, ok: !!session.url, error: session.url ? null : 'No URL returned' });
    } catch (e) {
      checks.push({ name: plan.name, ok: false, error: e.message });
    }
  }

  // 7. Auth Flow — tests JWT signing/verification and magic_links table directly
  // (avoids HTTP round-trip race condition when concurrent health checks consume the same token)
  try {
    await pool.query('SELECT COUNT(*) FROM magic_links WHERE expires_at > NOW()');
    const testToken = jwt.sign({ health: true, ts: Date.now() }, process.env.JWT_SECRET, { expiresIn: '1m' });
    const decoded = jwt.verify(testToken, process.env.JWT_SECRET);
    if (!decoded.health) throw new Error('JWT payload mismatch');
    checks.push({ name: 'Auth verify → JWT', ok: true });
  } catch (e) {
    checks.push({ name: 'Auth verify → JWT', ok: false, error: e.message });
  }

  // 8. Webhook endpoint reachable (should return 400 without valid signature — not 500)
  try {
    const whReq = await fetch('https://proofdeed.com/api/stripe-webhook', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'stripe-signature': 'test' },
      body: JSON.stringify({ type: 'test' }),
      signal: AbortSignal.timeout(10000),
    });
    // 400 = reachable and correctly rejecting invalid signature. 500 = broken.
    checks.push({ name: 'Webhook endpoint', ok: whReq.status === 400, error: whReq.status !== 400 ? `Expected 400, got ${whReq.status}` : null });
  } catch (e) {
    checks.push({ name: 'Webhook endpoint', ok: false, error: e.message });
  }

  // 9. Usage tracking — verify certifications table is accessible and queryable
  try {
    const usageRow = await pool.query('SELECT COUNT(*) FROM certifications');
    const totalCerts = parseInt(usageRow.rows[0].count);
    checks.push({ name: 'Usage tracking (certifications table)', ok: true, error: null, info: `${totalCerts} total certs` });
  } catch (e) {
    checks.push({ name: 'Usage tracking (certifications table)', ok: false, error: e.message });
  }

  const failures = checks.filter(c => !c.ok);

  // Increment streak for failing services, reset for healthy ones
  for (const f of failures) {
    failureStreak[f.name] = (failureStreak[f.name] || 0) + 1;
    console.warn(`[HealthMonitor] ${f.name} failure streak: ${failureStreak[f.name]}/${ALERT_AFTER_FAILURES}`);
  }
  for (const c of checks.filter(c => c.ok)) {
    if (failureStreak[c.name]) {
      // Recovered — send recovery email if we had previously alerted
      if (lastAlertSent[c.name]) {
        await sendAlertEmail(
          `✅ ProofDeed Recovery: ${c.name} is back online`,
          `ProofDeed system alert — ${new Date().toLocaleString()}\n\n${c.name} has recovered and is responding normally.\n\nDowntime streak: ${failureStreak[c.name]} checks (~${failureStreak[c.name] * 15} minutes)\n\nNo action needed.`
        ).catch(() => {});
        console.log(`[HealthMonitor] ${c.name} recovered — recovery email sent.`);
      } else {
        console.log(`[HealthMonitor] ${c.name} recovered after ${failureStreak[c.name]} check(s) — no alert was sent (blip).`);
      }
      delete failureStreak[c.name];
      delete lastAlertSent[c.name];
    }
  }

  // Only alert after 3 consecutive failures (~45 min of real downtime)
  for (const f of failures) {
    if (failureStreak[f.name] >= ALERT_AFTER_FAILURES) {
      const lastSent = lastAlertSent[f.name] || 0;
      // Re-alert every 2 hours if still down (not every check)
      if (now - lastSent > 2 * 60 * 60 * 1000) {
        lastAlertSent[f.name] = now;
        await sendAlertEmail(
          `🚨 ProofDeed Alert: ${f.name} has been DOWN for ~${failureStreak[f.name] * 15} minutes`,
          `ProofDeed system alert — ${new Date().toLocaleString()}\n\n${f.name} has failed ${failureStreak[f.name]} consecutive health checks (~${failureStreak[f.name] * 15} minutes of downtime).\n\nError: ${f.error}\n\nCheck DigitalOcean logs immediately:\nhttps://cloud.digitalocean.com\n\nYou will be notified again in 2 hours if still down, or immediately when it recovers.`
        ).catch(() => {});
        console.error(`[HealthMonitor] ALERT sent — ${f.name} down ${failureStreak[f.name]} checks: ${f.error}`);
      }
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
}, { timezone: 'Asia/Bangkok' });

// Startup health check — fires 30s after deploy so every new deploy emails a report
setTimeout(async () => {
  try {
    const checks = await runHealthChecks();
    const allOk = checks.every(c => c.ok);
    const lines = checks.map(c => `${c.ok ? '✅' : '❌'} ${c.name}${c.error ? ': ' + c.error : ''}`).join('\n');
    await sendAlertEmail(
      allOk ? '✅ ProofDeed Deploy Check — All Systems OK' : '⚠️ ProofDeed Deploy Check — Issues Detected',
      `ProofDeed System Report (post-deploy) — ${new Date().toLocaleDateString()}\n\n${lines}\n\nAdmin: https://proofdeed.com/admin`
    ).catch(() => {});
    console.log(`[HealthMonitor] Startup check complete. All OK: ${allOk}`);
  } catch (e) {
    console.error('[HealthMonitor] Startup check failed:', e.message);
  }
}, 30000); // 30 second delay to let server fully initialize

// Expose health check endpoint for manual trigger
app.get(['/api/admin/health-check', '/admin/health-check'], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: 'Unauthorized.' });
  const checks = await runHealthChecks();
  const allOk = checks.every(c => c.ok);
  res.json({ allOk, checks, timestamp: new Date().toISOString() });
});

/* ---------------- One-Time Article Pitch Sender ---------------- */
app.post(['/api/admin/send-articles', '/admin/send-articles'], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: 'Unauthorized.' });
  const { readFileSync } = await import('fs');
  const { fileURLToPath } = await import('url');
  const pathMod = await import('path');
  const __dir = pathMod.default.dirname(fileURLToPath(import.meta.url));

  const altaArticle = readFileSync(pathMod.default.join(__dir, 'outreach/article_alta.md'), 'utf8');
  const govtechArticle = readFileSync(pathMod.default.join(__dir, 'outreach/article_govtech.txt'), 'utf8');
  const igoArticle = readFileSync(pathMod.default.join(__dir, 'outreach/article_igo.txt'), 'utf8');

  const emails = [
    {
      to: 'service@alta.org',
      subject: 'Article Pitch — How Blockchain Certification Closes the Gap in Deed Fraud Prevention',
      text: `Dear TitleNews Editorial Team,\n\nI'm Scott Kiersten, Founder & CEO of ProofDeed LLC, a Veteran-Owned Small Business in Oshkosh, Wisconsin. We provide blockchain document certification for title companies and real estate attorneys — creating FRE Rule 901-admissible certificates at the moment of closing.\n\nI'd like to contribute an article for TitleNews: "Deed Fraud Is Happening After Closing — Here's the Technology That Stops It"\n\nThe piece is educational and objective. I can limit or remove any mention of ProofDeed per your guidelines. Full article below.\n\nScott Kiersten | Founder & CEO | ProofDeed LLC | VOSB\ninfo@proofdeed.com | proofdeed.com\n\n---\n\n${altaArticle}`
    },
    {
      to: 'lkinkade@govtech.com',
      subject: 'Guest Commentary Pitch — County Recorders Have a Document Fraud Problem. Blockchain Fixes It.',
      text: `Dear Lauren,\n\nI'm Scott Kiersten, Founder & CEO of ProofDeed LLC, a VOSB providing blockchain document certification for county recorder offices and government agencies.\n\nPitching a guest commentary for Govtech.com — policy and technology focused, not a product pitch. My company has submitted proposals to NSF SBIR and DHS LRBAA for this technology. Full article below.\n\nScott Kiersten | Founder & CEO | ProofDeed LLC | VOSB\ngov@proofdeed.com | proofdeed.com\n\n---\n\n${govtechArticle}`
    },
    {
      to: 'kim@iaogo.org',
      subject: 'Article for iGO Newsletter — After the FBI Warning on Deed Fraud: What Recorder Offices Can Do Right Now',
      text: `Dear Kim,\n\nI'm Scott Kiersten, Founder & CEO of ProofDeed LLC — blockchain document certification for county recorder offices.\n\nAsking if iGO's newsletter accepts contributed articles. Written a piece specifically for recorder audiences on closing the deed fraud gap the FBI warned about. Full article below.\n\nScott Kiersten | Founder & CEO | ProofDeed LLC | VOSB\ngov@proofdeed.com | proofdeed.com\n\n---\n\n${igoArticle}`
    }
  ];

  const { Resend: ResendClass } = await import('resend');
  const resendClient = new ResendClass(process.env.RESEND_API_KEY);
  const results = [];
  for (const email of emails) {
    try {
      const result = await resendClient.emails.send({
        from: 'Scott Kiersten <gov@proofdeed.com>',
        reply_to: 'gov@proofdeed.com',
        to: email.to,
        subject: email.subject,
        text: email.text
      });
      results.push({ to: email.to, status: 'sent', id: result.data?.id });
      await new Promise(r => setTimeout(r, 3000));
    } catch (err) {
      results.push({ to: email.to, status: 'failed', error: err.message });
    }
  }
  res.json({ results });
});

/* ---------------- Daily Health Check Endpoint ---------------- */
app.get(["/health-check", "/api/health-check"], async (req, res) => {
  // Secured with a secret token to prevent public abuse
  const token = req.headers["x-health-token"] || req.query.token;
  if (token !== process.env.HEALTH_CHECK_TOKEN) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const BASE = "https://proofdeed.com";
  const passed = [], failed = [], warnings = [];

  const testGet = (url) => new Promise((resolve) => {
    const https = require("https");
    const req = https.get(url, { timeout: 10000 }, (r) => resolve({ url, status: r.statusCode }));
    req.on("error", (e) => resolve({ url, status: 0, error: e.message }));
    req.on("timeout", () => { req.destroy(); resolve({ url, status: 0, error: "timeout" }); });
  });

  // Test key pages
  const pages = ["/", "/government", "/how-it-works", "/faq", "/login", "/verify", "/api-docs", "/privacy", "/terms"];
  for (const page of pages) {
    const r = await testGet(BASE + page);
    if (r.status === 200) passed.push(`${page} → 200`);
    else failed.push(`${page} → ${r.status || r.error}`);
  }

  // Test all 6 checkout plans
  const plans = ["starter-monthly", "starter-annual", "pro-monthly", "pro-annual", "enterprise", "government-pilot"];
  for (const plan of plans) {
    try {
      const session = await stripe.checkout.sessions.create({
        mode: plan === "government-pilot" ? "payment" : "subscription",
        ...(plan !== "government-pilot" ? { payment_method_types: ["card"] } : {}),
        line_items: [{ price: {
          "starter-monthly": process.env.PRICE_STARTER_MONTHLY,
          "starter-annual":  process.env.PRICE_STARTER_YEARLY,
          "pro-monthly":     process.env.PRICE_PRO_MONTHLY,
          "pro-annual":      process.env.PRICE_PRO_YEARLY,
          "enterprise":      process.env.PRICE_ENTERPRISE,
          "government-pilot":process.env.PRICE_GOVERNMENT_PILOT,
        }[plan], quantity: 1 }],
        success_url: "https://proofdeed.com/success",
        cancel_url: "https://proofdeed.com",
      });
      if (session.url) passed.push(`Checkout ${plan} → OK`);
      else failed.push(`Checkout ${plan} → no URL`);
    } catch (err) {
      failed.push(`Checkout ${plan} → ${err.message}`);
    }
  }

  // Test DB
  try {
    await pool.query("SELECT 1");
    passed.push("Database → connected");
  } catch (err) {
    failed.push(`Database → ${err.message}`);
  }

  // Send alert email if failures
  if (failed.length > 0 && process.env.RESEND_API_KEY) {
    try {
      await resend.emails.send({
        from: "ProofDeed Health Check <info@proofdeed.com>",
        to: "info@proofdeed.com",
        subject: `🚨 ProofDeed Health Check FAILED — ${failed.length} issue(s)`,
        text: `ProofDeed Daily Health Check — ${new Date().toUTCString()}\n\n❌ FAILED:\n${failed.map(f=>`  • ${f}`).join("\n")}\n\n✅ PASSED:\n${passed.map(p=>`  • ${p}`).join("\n")}\n\nFix: https://cloud.digitalocean.com/apps/753587e4-5e82-46af-a29e-a80b7dd60f87`,
      });
    } catch (e) { warnings.push("Alert email failed: " + e.message); }
  }

  const status = failed.length > 0 ? 500 : 200;
  res.status(status).json({
    timestamp: new Date().toISOString(),
    passed: passed.length,
    failed: failed.length,
    results: { passed, failed, warnings }
  });
});

/* ---------------- CRM Health Endpoint ---------------- */
app.get(['/api/admin/crm-health', '/admin/crm-health'], authRateLimit, async (req, res) => {
  if (!verifyAdminAuth(req)) return res.status(401).json({ error: 'Unauthorized.' });
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

    const [totals, byStatus, recentlySent, bounced, replied, followUpDue] = await Promise.all([
      pool.query(`SELECT COUNT(*) AS total FROM outreach_contacts`),
      pool.query(`SELECT status, COUNT(*) AS count FROM outreach_contacts GROUP BY status ORDER BY count DESC`),
      pool.query(`SELECT COUNT(*) AS count FROM outreach_contacts WHERE first_sent_at >= NOW() - INTERVAL '24 hours'`),
      pool.query(`SELECT COUNT(*) AS count FROM outreach_contacts WHERE status IN ('bounced','hard_bounce','suppressed')`),
      pool.query(`SELECT COUNT(*) AS count FROM outreach_contacts WHERE status = 'replied'`),
      pool.query(`
        SELECT COUNT(*) AS count FROM outreach_contacts
        WHERE status = 'sent'
          AND first_sent_at IS NOT NULL
          AND (
            (last_contact_at IS NULL AND first_sent_at <= NOW() - INTERVAL '7 days')
            OR last_contact_at <= NOW() - INTERVAL '7 days'
          )
      `),
    ]);

    const recentContacts = await pool.query(`
      SELECT name, email, company, status, first_sent_at, last_contact_at, pipeline_stage
      FROM outreach_contacts
      ORDER BY last_contact_at DESC NULLS LAST, created_at DESC
      LIMIT 10
    `);

    res.json({
      timestamp: new Date().toISOString(),
      summary: {
        total_contacts: parseInt(totals.rows[0].total),
        sent_last_24h: parseInt(recentlySent.rows[0].count),
        bounced: parseInt(bounced.rows[0].count),
        replied: parseInt(replied.rows[0].count),
        follow_up_due: parseInt(followUpDue.rows[0].count),
      },
      by_status: byStatus.rows.map(r => ({ status: r.status, count: parseInt(r.count) })),
      recent_contacts: recentContacts.rows,
    });
  } catch (err) {
    console.error('CRM health error:', err);
    res.status(500).json({ error: 'Failed to load CRM health.' });
  }
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
