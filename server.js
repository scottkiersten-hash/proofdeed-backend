import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import cors from 'cors';
import formData from 'form-data';
import Mailgun from 'mailgun.js';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import pkg from 'pg';

const { Pool } = pkg;

/* -------------------- ENV VALIDATION -------------------- */

if (!process.env.MAILGUN_API_KEY) {
  console.error("❌ MAILGUN_API_KEY missing");
  process.exit(1);
}

if (!process.env.MAILGUN_DOMAIN) {
  console.error("❌ MAILGUN_DOMAIN missing");
  process.exit(1);
}

if (!process.env.DATABASE_URL) {
  console.error("❌ DATABASE_URL missing");
  process.exit(1);
}

/* -------------------- APP SETUP -------------------- */

const app = express();
app.set('trust proxy', 1);

const PORT = process.env.PORT || 8080;

app.use(helmet());
app.use(cors());
app.use(express.json());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later.'
});

app.use(limiter);

/* -------------------- DATABASE -------------------- */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

pool.connect()
  .then(client => {
    console.log("✅ Database connected");
    client.release();
  })
  .catch(err => {
    console.error("❌ Database connection error:", err);
  });

/* -------------------- MAILGUN -------------------- */

const mailgun = new Mailgun(formData);

const mg = mailgun.client({
  username: 'api',
  key: process.env.MAILGUN_API_KEY,
  url: 'https://api.mailgun.net'
});

/* -------------------- HEALTH CHECK -------------------- */

app.get('/', (req, res) => {
  res.send('ProofDeed backend running');
});

/* -------------------- INQUIRY -------------------- */

app.post('/inquiry', async (req, res) => {
  try {
    const { name, email, message } = req.body;

    if (!name || !email || !message) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields'
      });
    }

    await mg.messages.create(process.env.MAILGUN_DOMAIN, {
      from: `ProofDeed <${process.env.MAIL_FROM}>`,
      to: [process.env.MAIL_TO],
      subject: 'New Inquiry Submission',
      text: `
Name: ${name}
Email: ${email}

Message:
${message}
      `
    });

    return res.json({ success: true });

  } catch (error) {
    console.error('❌ Mailgun error:', error);
    return res.status(500).json({
      success: false,
      error: 'Email failed to send'
    });
  }
});

/* -------------------- CHECKOUT INTENT -------------------- */

app.post('/api/checkout-intent', async (req, res) => {
  try {
    const { plan, email } = req.body;

    if (!plan || !email) {
      return res.status(400).json({ success: false });
    }

    console.log(`Checkout started: ${plan} - ${email}`);

    return res.json({ success: true });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false });
  }
});

/* -------------------- START SERVER -------------------- */

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
