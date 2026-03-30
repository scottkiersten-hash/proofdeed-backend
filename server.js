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
    res.status(500).json({ error: error.message });
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
    res.status(500).json({ error: error.message });
  }
});

/* ---------------- MAGIC LINK - SEND ---------------- */
app.post(["/auth/magic-link", "/api/auth/magic-link"], async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || !email.includes("@")) {
      return res.status(400).json({ error: "Valid email required." });
    }

    const userCheck = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

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
    res.status(500).json({ error: error.message });
  }
});

/* ---------------- MAGIC LINK - VERIFY ---------------- */
app.get(["/auth/verify", "/api/auth/verify"], async (req, res) => {
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
    res.status(500).json({ error: error.message });
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

    res.json({
      certifications: certs.rows,
      used,
      limit,
      plan
    });

  } catch (error) {
    console.error("User certifications error:", error);
    res.status(500).json({ error: error.message });
  }
});

/* ---------------- ENTERPRISE - GENERATE API KEY ---------------- */
app.post("/api/enterprise/generate-key", async (req, res) => {
  try {
    const adminSecret = req.headers["x-admin-secret"];
    if (adminSecret !== process.env.ADMIN_SECRET) {
      return res.status(401).json({ error: "Unauthorized." });
    }

    const { email, monthly_limit, stripe_customer_id, stripe_subscription_id } = req.body;
    if (!email) return res.status(400).json({ error: "Email required." });

    const apiKey = "pd_live_" + crypto.randomBytes(32).toString("hex");

    await pool.query(
      `INSERT INTO api_keys (email, api_key, plan, monthly_limit, used_this_month, active, created_at)
       VALUES ($1, $2, 'enterprise', $3, 0, TRUE, NOW())
       ON CONFLICT (email) DO UPDATE SET api_key = $2, monthly_limit = $3, active = TRUE`,
      [email, apiKey, monthly_limit || 1000]
    );

    if (stripe_customer_id && stripe_subscription_id) {
      await pool.query(
        `INSERT INTO users (email, stripe_customer_id, subscription_id, created_at)
         VALUES ($1, $2, $3, NOW())
         ON CONFLICT (email) DO UPDATE SET stripe_customer_id = $2, subscription_id = $3`,
        [email, stripe_customer_id, stripe_subscription_id]
      );
    }

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
          text: "Welcome to ProofDeed Enterprise.\n\nYour API Key: " + apiKey + "\n\nMonthly Limit: " + (monthly_limit || 1000) + " certifications\n\nAPI Documentation: https://proofdeed.com/api-docs\n\nProofDeed\nhttps://proofdeed.com"
        })
      });
    }

    res.json({ success: true, apiKey, email, monthly_limit: monthly_limit || 1000 });

  } catch (error) {
    console.error("Generate API key error:", error);
    res.status(500).json({ error: error.message });
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

    await pool.query(
      "UPDATE api_keys SET used_this_month = used_this_month + 1 WHERE api_key = $1",
      [req.apiKey.api_key]
    );

    if (req.apiKey.webhook_url) {
      try {
        await fetch(req.apiKey.webhook_url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ proofId, documentHash, timestamp, polygon_tx, event: "certification.created" })
        });
      } catch (webhookErr) {
        console.error("Webhook delivery failed (non-fatal):", webhookErr.message);
      }
    }

    res.json({ proofId, timestamp, polygon_tx, hash: documentHash, used: req.apiKey.used_this_month + 1, limit: req.apiKey.monthly_limit });

  } catch (error) {
    console.error("Enterprise certify error:", error);
    res.status(500).json({ error: error.message });
  }
});

/* ---------------- ENTERPRISE - BATCH CERTIFY ---------------- */
app.post("/api/v1/batch", authenticateApiKey, async (req, res) => {
  try {
    const { documents } = req.body;

    if (!Array.isArray(documents) || documents.length === 0) {
      return res.status(400).json({ error: "documents array required." });
    }

    if (documents.length > 100) {
      return res.status(400).json({ error: "Maximum 100 documents per batch." });
    }

    const remaining = req.apiKey.monthly_limit - req.apiKey.used_this_month;
    if (documents.length > remaining) {
      return res.status(429).json({ error: "Batch size exceeds remaining limit. Remaining: " + remaining });
    }

    const results = [];

    for (const doc of documents) {
      const { documentHash, id } = doc;

      if (!documentHash || typeof documentHash !== "string" || documentHash.length !== 64) {
        results.push({ id, error: "Invalid hash", documentHash });
        continue;
      }

      const proofId = "PD-" + Date.now() + "-" + Math.random().toString(36).substr(2, 5);
      const timestamp = new Date().toISOString();

      let polygon_tx = null;
      try {
        polygon_tx = await anchorToPolygon(documentHash);
      } catch (err) {
        console.error("Blockchain failed for doc:", documentHash);
      }

      await pool.query(
        `INSERT INTO certifications (certification_id, hash, polygon_tx, created_at)
         VALUES ($1, $2, $3, NOW())
         ON CONFLICT (certification_id) DO NOTHING`,
        [proofId, documentHash, polygon_tx]
      );

      results.push({ id, proofId, documentHash, timestamp, polygon_tx });
    }

    await pool.query(
      "UPDATE api_keys SET used_this_month = used_this_month + $1 WHERE api_key = $2",
      [results.filter(r => !r.error).length, req.apiKey.api_key]
    );

    res.json({
      success: true,
      processed: results.filter(r => !r.error).length,
      failed: results.filter(r => r.error).length,
      results
    });

  } catch (error) {
    console.error("Batch certify error:", error);
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

    if (mailgunDomain && mailgunApiKey) {
      const isProofEmail = !!proofId;
      const emailSubject = subject || (isProofEmail ? "Your ProofDeed Certificate" : "ProofDeed Contact Confirmation");
      const emailBody = isProofEmail
        ? "Thank you for using ProofDeed.\n\nYour document has been permanently recorded on the Polygon blockchain.\n\nProof ID: " + proofId + "\nDocument Hash: " + documentHash + "\nTimestamp: " + timestamp + "\n\nVerify your document at:\nhttps://proofdeed.com/verify\n\nProofDeed\nhttps://proofdeed.com"
        : "New contact submission from ProofDeed.\n\nName: " + name + "\nEmail: " + email + "\nOrganization: " + (resolvedCompany || "N/A") + "\nPhone: " + (phone || "N/A") + "\nMessage: " + (resolvedNotes || "N/A") + "\n\nProofDeed\nhttps://proofdeed.com";

      try {
        await fetch("https://api.mailgun.net/v3/" + mailgunDomain + "/messages", {
          method: "POST",
          headers: {
            "Authorization": "Basic " + Buffer.from("api:" + mailgunApiKey).toString("base64"),
            "Content-Type": "application/x-www-form-urlencoded"
          },
          body: new URLSearchParams({
            from: process.env.MAIL_FROM || "ProofDeed <mailgun@" + mailgunDomain + ">",
            to: process.env.MAIL_TO || email,
            subject: emailSubject,
            text: emailBody
          })
        });
        console.log("Email sent to " + email);
      } catch (mailErr) {
        console.error("Mailgun error (non-fatal):", mailErr.message);
      }
    }

    console.log("New " + (request_type || "contact") + " submission from: " + email);
    res.json({ success: true });

  } catch (error) {
    console.error("Contact form error:", error);
    res.status(500).json({ error: error.message });
  }
});

/* ---------------- STRIPE CHECKOUT ---------------- */
app.post(["/create-checkout-session", "/api/create-checkout-session"], async (req, res) => {
  try {
    const { plan, success_url, cancel_url, referral } = req.body;

    const priceMap = {
      "starter-monthly": process.env.PRICE_STARTER_MONTHLY,
      "starter-annual":  process.env.PRICE_STARTER_YEARLY,
      "pro-monthly":     process.env.PRICE_PRO_MONTHLY,
      "pro-annual":      process.env.PRICE_PRO_YEARLY,
    };

    const priceId = priceMap[plan];
    if (!priceId) return res.status(400).json({ error: "Invalid plan: " + plan });

    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      payment_method_types: ["card"],
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: success_url || "https://proofdeed.com/success",
      cancel_url: cancel_url || "https://proofdeed.com",
      client_reference_id: referral || null
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
    return res.status(400).send("Webhook Error: " + err.message);
  }

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    const email = session.customer_details?.email;
    const customerId = session.customer;
    const subscriptionId = session.subscription;
    const referral = session.client_reference_id;

    console.log("New subscriber:", email);

    try {
      await pool.query(
        `INSERT INTO users (email, stripe_customer_id, subscription_id, referred_by, created_at)
         VALUES ($1, $2, $3, $4, NOW())
         ON CONFLICT (email) DO UPDATE
         SET stripe_customer_id = $2, subscription_id = $3`,
        [email, customerId, subscriptionId, referral || null]
      );

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

    } catch (dbErr) {
      console.error("User creation failed:", dbErr.message);
    }
  }

  res.json({ received: true });
});
/* ---------------- ADMIN DASHBOARD ---------------- */
app.get(["/admin/stats", "/api/admin/stats"], async (req, res) => {
  try {
    const adminSecret = req.headers["x-admin-secret"];
    if (adminSecret !== process.env.ADMIN_SECRET) {
      return res.status(401).json({ error: "Unauthorized." });
    }

    const users = await pool.query(
      `SELECT email, stripe_customer_id, subscription_id, referral_code, 
       referred_by, revenue_generated, created_at 
       FROM users ORDER BY created_at DESC`
    );

    const certs = await pool.query(
      `SELECT COUNT(*) as total FROM certifications`
    );

    const contacts = await pool.query(
      `SELECT name, email, company, notes, request_type, created_at 
       FROM contact_submissions ORDER BY created_at DESC LIMIT 50`
    );

    const apiKeys = await pool.query(
      `SELECT email, plan, monthly_limit, used_this_month, active, created_at 
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
    res.status(500).json({ error: error.message });
  }
});
/* ---------------- MONTHLY USAGE RESET ---------------- */
async function resetMonthlyUsage() {
  try {
    const now = new Date();
    if (now.getDate() === 1 && now.getHours() === 0) {
      await pool.query('UPDATE api_keys SET used_this_month = 0');
      console.log('Monthly API key usage reset completed.');
    }
  } catch (err) {
    console.error('Monthly reset error:', err.message);
  }
}

setInterval(resetMonthlyUsage, 60 * 60 * 1000);

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
    res.status(500).json({ error: err.message });
  }
});
/* ---------------- Start Server ---------------- */
app.listen(PORT, () => {
  console.log("ProofDeed backend running on port " + PORT);
});
