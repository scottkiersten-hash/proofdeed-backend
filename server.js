import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import formData from 'form-data';
import Mailgun from 'mailgun.js';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';

dotenv.config();

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 8080;

/* -------------------- SECURITY -------------------- */

// Security headers
app.use(helmet());

// Basic rate limiting (100 requests per 15 minutes per IP)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later.'
});

app.use(limiter);

app.use(cors());
app.use(express.json());

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
app.post('/api/checkout-intent', async (req, res) => {
  try {
    const { plan, email } = req.body;

    if (!plan || !email) {
      return res.status(400).json({ success: false });
    }

    console.log(`Checkout started: ${plan} - ${email}`);

    return res.json({ success: true });

  } catch (err) {
    return res.status(500).json({ success: false });
  }
});
/* -------------------- START SERVER -------------------- */
/* -------------------- SIGNUP -------------------- */

app.post('/signup', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        error: 'Email required'
      });
    }

    console.log(`New signup attempt: ${email}`);

    return res.json({
      success: true,
      message: 'Signup registered'
    });

  } catch (error) {
    return res.status(500).json({
      success: false
    });
  }
});
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
