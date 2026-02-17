import express from "express";
import cors from "cors";
import nodemailer from "nodemailer";
import { v4 as uuidv4 } from "uuid";

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 8080;

/* ======================
   EMAIL CONFIG
====================== */
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

/* ======================
   HEALTH
====================== */
app.get("/", (req, res) => {
  res.json({ status: "ProofDeed Backend Active" });
});

/* ======================
   GOVERNMENT CONTACT
====================== */
app.post("/api/gov/contact", async (req, res) => {
  const { name, agency, email, message, website } = req.body;

  if (website) return res.status(400).json({ error: "Bot detected" });
  if (!name || !agency || !email || !message) {
    return res.status(400).json({ error: "Missing fields" });
  }

  const leadId = uuidv4();

  try {
    await transporter.sendMail({
      from: `"ProofDeed Website" <${process.env.SMTP_USER}>`,
      to: "info@proofdeed.com",
      replyTo: email,
      subject: `Government Access Request – ${agency}`,
      text: `
Name: ${name}
Agency: ${agency}
Email: ${email}

Message:
${message}

Lead ID: ${leadId}
      `
    });

    res.json({ success: true, leadId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Email failed" });
  }
});

/* ======================
   START
====================== */
app.listen(PORT, () => {
  console.log(`Backend running on ${PORT}`);
});
