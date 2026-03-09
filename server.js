import dotenv from 'dotenv';
dotenv.config();

import anchorToPolygon from "./polygon.js";
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import Stripe from 'stripe';
import OpenAI from 'openai';
import crypto from 'crypto';
import PDFDocument from 'pdfkit';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const app = express();
const PORT = process.env.PORT || 8080;

/* ===========================
TEMP STORAGE
=========================== */

const users = [];
const certifications = [];

/* ===========================
ENV VALIDATION
=========================== */

if (!process.env.STRIPE_SECRET_KEY) {
  console.warn("⚠️ STRIPE_SECRET_KEY not set");
}

if (!process.env.FRONTEND_URL) {
  console.warn("⚠️ FRONTEND_URL not set");
}

if (!process.env.OPENAI_API_KEY) {
  console.warn("⚠️ OPENAI_API_KEY not set");
}

if (!process.env.JWT_SECRET) {
  console.warn("⚠️ JWT_SECRET not set");
}

/* ===========================
INIT CLIENTS
=========================== */

const stripe = process.env.STRIPE_SECRET_KEY
  ? new Stripe(process.env.STRIPE_SECRET_KEY)
  : null;

const openai = process.env.OPENAI_API_KEY
  ? new OpenAI({ apiKey: process.env.OPENAI_API_KEY })
  : null;

/* ===========================
SECURITY + MIDDLEWARE
=========================== */

app.set('trust proxy', 1);

app.use(helmet());
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

app.use(cors({
  origin: [
    'https://proofdeed.com',
    'https://www.proofdeed.com',
    process.env.FRONTEND_URL
  ].filter(Boolean),
  credentials: true
}));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
}));

/* ===========================
AUTH MIDDLEWARE
=========================== */

function authenticateToken(req, res, next) {

  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ error: "Token required" });
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, process.env.JWT_SECRET || "dev_secret", (err, user) => {

    if (err) {
      return res.status(403).json({ error: "Invalid token" });
    }

    req.user = user;
    next();

  });

}

/* ===========================
HEALTH
=========================== */

app.get('/', (req, res) => {
  res.status(200).send('ProofDeed backend running');
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

/* ===========================
AI TEST ROUTE
=========================== */

app.get('/api/ai-test', async (req, res) => {

  try {

    if (!openai) {
      return res.status(500).json({
        error: "OpenAI not configured"
      });
    }

    const response = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: "You are ProofDeed AI." },
        { role: "user", content: "Say AI is connected." }
      ]
    });

    res.json({
      success: true,
      reply: response.choices[0].message.content
    });

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: "AI test failed"
    });

  }

});

/* ===========================
STRIPE CHECKOUT SESSION
=========================== */

app.get('/api/create-checkout-session', async (req, res) => {

  try {

    if (!stripe) {
      return res.status(500).json({ error: "Stripe not configured" });
    }

    const { price } = req.query;

    const priceMap = {
      PRICE_STARTER_MONTHLY: process.env.PRICE_STARTER_MONTHLY,
      PRICE_STARTER_YEARLY: process.env.PRICE_STARTER_YEARLY,
      PRICE_PRO_MONTHLY: process.env.PRICE_PRO_MONTHLY,
      PRICE_PRO_YEARLY: process.env.PRICE_PRO_YEARLY
    };

    const stripePrice = priceMap[price];

    if (!stripePrice) {
      return res.status(400).json({ error: "Invalid price id" });
    }

    const session = await stripe.checkout.sessions.create({

      mode: "subscription",

      line_items: [
        {
          price: stripePrice,
          quantity: 1
        }
      ],

      success_url: "https://proofdeed.com/success?session_id={CHECKOUT_SESSION_ID}",
      cancel_url: "https://proofdeed.com/document",

      billing_address_collection: "auto"

    });

    res.redirect(303, session.url);

  } catch (error) {

    console.error("Stripe session error:", error);

    res.status(500).json({
      error: "Stripe session creation failed"
    });

  }

});

/* ===========================
USER SIGNUP
=========================== */

app.post('/api/signup', async (req, res) => {

  try {

    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password required" });
    }

    const existing = users.find(u => u.email === email);

    if (existing) {
      return res.status(400).json({ error: "User already exists" });
    }

    const hashed = await bcrypt.hash(password, 10);

    const user = {
      id: crypto.randomUUID(),
      email,
      password: hashed
    };

    users.push(user);

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET || "dev_secret",
      { expiresIn: "7d" }
    );

    res.json({
      success: true,
      token
    });

  } catch (err) {

    console.error(err);
    res.status(500).json({ error: "Signup failed" });

  }

});

/* ===========================
USER LOGIN
=========================== */

app.post('/api/login', async (req, res) => {

  try {

    const { email, password } = req.body;

    const user = users.find(u => u.email === email);

    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const valid = await bcrypt.compare(password, user.password);

    if (!valid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET || "dev_secret",
      { expiresIn: "7d" }
    );

    res.json({
      success: true,
      token
    });

  } catch (err) {

    console.error(err);
    res.status(500).json({ error: "Login failed" });

  }

});

/* ===========================
CERTIFY DOCUMENT
=========================== */

app.post('/api/certify-document', authenticateToken, async (req, res) => {

  try {

    if (!openai) {
      return res.status(500).json({ error: "OpenAI not configured" });
    }

    const { document } = req.body;

    if (!document) {
      return res.status(400).json({ error: "Document text required" });
    }

    const hash = crypto
      .createHash('sha256')
      .update(document)
      .digest('hex');

    await anchorToPolygon(hash);

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

    const record = {
      certification_id,
      timestamp,
      hash,
      user_id: req.user.id,
      document_data: extracted
    };

    certifications.push(record);

    return res.json({
      success: true,
      certification_id,
      hash,
      timestamp,
      document_data: extracted
    });

  } catch (err) {

    console.error("Certification error:", err);

    return res.status(500).json({
      error: "Certification failed"
    });

  }

});

/* ===========================
USER CERTIFICATIONS
=========================== */

app.get('/api/my-certifications', authenticateToken, (req, res) => {

  const userCerts = certifications.filter(
    c => c.user_id === req.user.id
  );

  res.json({
    certifications: userCerts
  });

});

/* ===========================
VIEW CERTIFICATE
=========================== */

app.get('/api/certificate/:id', (req, res) => {

  const cert = certifications.find(
    c => c.certification_id === req.params.id
  );

  if (!cert) {
    return res.status(404).json({
      error: "Certificate not found"
    });
  }

  res.json(cert);

});

/* ===========================
PDF CERTIFICATE
=========================== */

app.get('/api/certificate/:id/pdf', (req, res) => {

  const cert = certifications.find(
    c => c.certification_id === req.params.id
  );

  if (!cert) {
    return res.status(404).json({
      error: "Certificate not found"
    });
  }

  const doc = new PDFDocument();

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader(
    'Content-Disposition',
    `attachment; filename="ProofDeed-${cert.certification_id}.pdf"`
  );

  doc.pipe(res);

  doc.fontSize(24).text("PROOFDEED CERTIFICATE", { align: 'center' });

  doc.moveDown();

  doc.fontSize(14).text(`Certification ID: ${cert.certification_id}`);
  doc.text(`Timestamp: ${cert.timestamp}`);
  doc.text(`Hash: ${cert.hash}`);

  doc.moveDown();

  doc.text("Document Data:");

  Object.entries(cert.document_data).forEach(([key, value]) => {
    doc.text(`${key}: ${value}`);
  });

  doc.moveDown();

  doc.text("Certified by ProofDeed");
  doc.text("https://proofdeed.com");

  doc.end();

});
/* ===========================
VERIFY STRIPE PAYMENT
=========================== */

app.get('/api/verify-payment', async (req, res) => {

  try {

    if (!stripe) {
      return res.status(500).json({
        error: "Stripe not configured"
      });
    }

    const { session_id } = req.query;

    if (!session_id) {
      return res.status(400).json({
        error: "Missing session_id"
      });
    }

    const session = await stripe.checkout.sessions.retrieve(session_id);

    if (session.payment_status !== "paid") {
      return res.status(400).json({
        success: false,
        status: session.payment_status
      });
    }

    res.json({
      success: true,
      customer: session.customer,
      subscription: session.subscription
    });

  } catch (err) {

    console.error("Verify payment error:", err);

    res.status(500).json({
      error: "Verification failed"
    });

  }

});
/* ===========================
START SERVER
=========================== */

app.listen(PORT, () => {
  console.log("🚀 Server running on port " + PORT);
});
