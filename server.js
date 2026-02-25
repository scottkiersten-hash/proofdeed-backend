import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import formData from 'form-data';
import Mailgun from 'mailgun.js';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import pkg from 'pg';

dotenv.config();

const { Pool } = pkg;

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 8080;

/* -------------------- SECURITY -------------------- */

app.use(helmet());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later.'
});

app.use(limiter);
app.use(cors());
app.use(express.json());

/* -------------------- DATABASE SETUP -------------------- */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production'
    ? { rejectUnauthorized: false }
    : false
});

// Test DB connection on startup
pool.connect()
  .then(() => console.log('Database connected successfully'))
  .catch(err => console.error('Database connection error:', err));

/* -------------------- MAILGUN SETUP -------------------- */

const mailgun = new Mailgun(formData);
const mg = mailgun.client({
  username: 'api',
  key: process.env.MAILGUN_API_KEY
});

/* -------------------- HEALTH CHECK -------------------- */

app.get('/', (req, res) => {
  res.send('ProofDeed backend running');
});

/* -------------------- SIGNUP ENDPOINT -------------------- */

app.post('/signup', async (req, res) => {
  try {
    const { email, vertical, plan } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        error: 'Email required'
      });
    }

    await pool.query(
      'INSERT INTO users (email, vertical, plan) VALUES ($1, $2, $3)',
      [email, vertical || 'document', plan || 'starter']
    );

    return res.json({ success: true });

  } catch (error) {
    console.error('Signup error:', error);
    return res.status(500).json({
      success: false,
      error: 'Database error'
    });
  }
});

/* -------------------- INQUIRY ENDPOINT -------------------- */

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
      from: `ProofDeed <mailgun@${process.env.MAILGUN_DOMAIN}>`,
      to: ['info@proofdeed.com'],
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
    console.error('Mailgun error:', error);
    return res.status(500).json({
      success: false,
      error: 'Email failed to send'
    });
  }
});

/* -------------------- START SERVER -------------------- */

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
