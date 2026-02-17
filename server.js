import express from "express";
import cors from "cors";
import { v4 as uuidv4 } from "uuid";

const app = express();

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 8080;

// ======================
// Utility
// ======================
function auditLog(type, payload) {
  console.log(`[AUDIT] ${type}`, payload);
}

function rateLimitCheck() {
  return false;
}

// ======================
// Health
// ======================
app.get("/", (_req, res) => {
  res.json({
    status: "ProofDeed Backend Active",
    timestamp: new Date().toISOString(),
  });
});

// ======================
// GOVERNMENT CONTACT
// ======================
app.post("/api/gov/contact", (req, res) => {
  const { name, agency, email, message, website } = req.body;

  if (website) return res.status(400).json({ error: "Bot detected" });
  if (!name || !agency || !email)
    return res.status(400).json({ error: "Missing required fields" });

  const leadId = uuidv4();
  auditLog("GOV_CONTACT", { leadId, name, agency, email, message });

  res.json({ success: true, leadId });
});

// ======================
// AUTO
// ======================
app.post("/api/auto/intake", (req, res) => {
  const { vin, buyer, seller, price, state, website } = req.body;

  if (website) return res.status(400).json({ error: "Bot detected" });
  if (!vin || !buyer || !seller || !price || !state)
    return res.status(400).json({ error: "Missing required fields" });

  const submissionId = uuidv4();
  auditLog("AUTO_INTAKE", { submissionId, vin });

  res.json({ success: true, submissionId });
});

// ======================
// NOTARY
// ======================
app.post("/api/notary/intake", (req, res) => {
  const { documentType, partyA, partyB, county, state, website } = req.body;

  if (website) return res.status(400).json({ error: "Bot detected" });
  if (!documentType || !partyA || !partyB)
    return res.status(400).json({ error: "Missing required fields" });

  const recordId = uuidv4();
  auditLog("NOTARY_INTAKE", { recordId, documentType });

  res.json({ success: true, recordId });
});

// ======================
// START SERVER
// ======================
app.listen(PORT, () => {
  console.log(`ProofDeed backend running on port ${PORT}`);
});
