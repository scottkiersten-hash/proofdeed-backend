const express = require("express");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");

const app = express();
app.use(express.json());

// =======================
// In-memory storage (MVP)
// =======================

const proofs = [];
const affiliates = [];

// =======================
// Helpers
// =======================

function generateHash(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

// =======================
// Health Check (DigitalOcean needs this)
// =======================

app.get("/", (req, res) => {
  res.status(200).json({ status: "ProofDeed backend running" });
});

// =======================
// Proofs
// =======================

app.get("/proofs", (req, res) => {
  res.json({
    count: proofs.length,
    proofs
  });
});

app.post("/proofs", (req, res) => {
  const { data, metadata } = req.body;

  if (!data) {
    return res.status(400).json({ error: "Data is required" });
  }

  const proof = {
    id: uuidv4(),
    data,
    metadata: metadata || {},
    hash: generateHash(data + JSON.stringify(metadata || {})),
    timestamp: new Date().toISOString()
  };

  proofs.push(proof);

  res.json({ success: true, proof });
});

// =======================
// Affiliates
// =======================

app.post("/affiliates/signup", (req, res) => {
  const { name, email } = req.body;

  if (!name || !email) {
    return res.status(400).json({ error: "Name and email required" });
  }

  const affiliate = {
    id: uuidv4(),
    name,
    email,
    referrals: 0,
    createdAt: new Date().toISOString()
  };

  affiliates.push(affiliate);

  res.json({ success: true, affiliate });
});

app.get("/affiliates", (req, res) => {
  res.json({
    count: affiliates.length,
    affiliates
  });
});

// =======================
// START SERVER (DO SAFE)
// =======================

const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`ProofDeed backend running on port ${PORT}`);
});
