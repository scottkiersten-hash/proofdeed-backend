import express from "express";
import cors from "cors";
import formData from "form-data";
import Mailgun from "mailgun.js";

const app = express();
app.use(cors());
app.use(express.json());

const mailgun = new Mailgun(formData);
const mg = mailgun.client({
  username: "api",
  key: process.env.MAILGUN_API_KEY,
  url: process.env.MAILGUN_BASE_URL
});

app.post("/api/contact", async (req, res) => {
  const { name, email, message } = req.body;

  try {
    await mg.messages.create(process.env.MAILGUN_DOMAIN, {
      from: process.env.MAIL_FROM,
      to: process.env.MAIL_TO,
      subject: "New ProofDeed Contact Form Submission",
      text: `
Name: ${name}
Email: ${email}

Message:
${message}
      `
    });

    res.json({ success: true });
  } catch (error) {
    console.error("Mailgun error:", error);
    res.status(500).json({ success: false, error: "Email failed" });
  }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
