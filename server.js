import express from "express";
import cors from "cors";
import crypto from "crypto";
import { v4 as uuidv4 } from "uuid";
import nodemailer from "nodemailer";

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 8080;

// ======================
// EMAIL CONFIG (SMTP)
// ======================

const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

async function sendEmail(subject, body) {
  await mailer.sendMail({
    from: `"ProofDeed" <info@proofdeed.com>`,
    to: "info@proofdeed.com",
    subject,
    text: body
  });
}

// ======================
// Utility
// ======================

function auditLog(type, payload) {
  console.log(`[AUDIT] ${type}`, payload);
}

function rateLimitCheck(req) {
  return false;
}

// ======================
// Health
// ======================

app.get("/", (req, res) => {
  res.json({
    status: "ProofDeed Backend Active",
    timestamp: new Date().toISOString()
  });
});

// ======================
// GOVERNMENT CONTACT
// ======================

app.post("/api/gov/contact", async (req, res) => {
  try {
    if (rateLimitCheck(req)) {
      return res.status(429).json({ error: "Too many attempts." });
    }

    const { name, agency, email, message, website } = req.body;
    if (website) return res.status(400).json({ error: "Bot detected." });

    if (!name || !agency || !email) {
      return res.status(400).json({ error: "Missing required fields." });
    }

    const leadId = uuidv4();

    await sendEmail(
      "Government Access Request",
      `
Lead ID: ${leadId}
Name: ${name}
Agency: ${agency}
Email: ${email}

Message:
${message || "N/A"}
`
    );

    auditLog("GOV_CONTACT", { leadId, name, agency, email });

    res.json({ success: true, leadId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Email failed." });
  }
});

// ======================
// AUTOMOTIVE
// ======================

app.post("/api/auto/intake", async (req, res) => {
  try {
    const { vin, buyer, seller, price, state, website } = req.body;
    if (website) return res.status(400).json({ error: "Bot detected." });

    if (!vin || !buyer || !seller || !price || !state) {
      return res.status(400).json({ error: "Missing required fields." });
    }

    const submissionId = uuidv4();

    await sendEmail(
      "Automotive Intake",
      `
Submission ID: ${submissionId}
VIN: ${vin}
Buyer: ${buyer}
Seller: ${seller}
Price: ${price}
State: ${state}
`
    );

    auditLog("AUTO_INTAKE", { submissionId, vin });

    res.json({ success: true, submissionId });
  } catch {
    res.status(500).json({ error: "Email failed." });
  }
});

// ======================
// NOTARY / REAL ESTATE
// ======================

app.post("/api/notary/intake", async (req, res) => {
  try {
    const { documentType, partyA, partyB, county, state, website } = req.body;
    if (website) return res.status(400).json({ error: "Bot detected." });

    if (!documentType || !partyA || !partyB) {
      return res.status(400).json({ error: "Missing required fields." });
    }

    const recordId = uuidv4();

    await sendEmail(
      "Notary Intake",
      `
Record ID: ${recordId}
Document: ${documentType}
Party A: ${partyA}
Party B: ${partyB}
County: ${county || "N/A"}
State: ${state || "N/A"}
`
    );

    auditLog("NOTARY_INTAKE", { recordId, documentType });

    res.json({ success: true, recordId });
  } catch {
    res.status(500).json({ error: "Email failed." });
  }
});

// ======================
// FRAUD CHECK (Future)
// ======================

app.post("/api/gov/fraud-check", (req, res) => {
  const { recordId } = req.body;
  auditLog("GOV_FRAUD_CHECK", { recor
