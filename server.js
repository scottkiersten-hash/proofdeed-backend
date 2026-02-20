import express from "express";
import cors from "cors";
import formData from "form-data";
import Mailgun from "mailgun.js";

const app = express();

app.use(cors());
app.use(express.json());

/*
|--------------------------------------------------------------------------
| Mailgun Setup
|--------------------------------------------------------------------------
*/

const mailgun = new Mailgun(formData);

const mg = mailgun.client({
  username: "api",
  key: process.env.MAILGUN_API_KEY,
  url: process.env.MAILGUN_BASE_URL || "https://api.mailgun.net",
});

/*
|--------------------------------------------------------------------------
| Routes
|--------------------------------------------------------------------------
*/

app.get("/", (req, res) => {
  res.send("ProofDeed Backend Running");
});

app.post("/api/contact", async (req, res) => {
  try {
    const { name, email, message } = req.body;

    await mg.messages.create(process.env.MAILGUN_DOMAIN, {
      from: process.env.MAIL_FROM,
      to: process.env.MAIL_TO,
      subject: "New Contact Form Submission",
      text: `
Name: ${name}
Email: ${email}

Message:
${message}
      `,
    });

    res.status(200).json({ success: true });
  } catch (error) {
    console.error("Mailgun Error:", error);
    res.status(500).json({ success: false, error: "Email failed to send" });
  }
});

/*
|--------------------------------------------------------------------------
| Start Server
|--------------------------------------------------------------------------
*/

const PORT = process.env.PORT || 8080;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
