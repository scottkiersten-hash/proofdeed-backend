// ProofDeed Clean MVP Backend
// Created Feb 4, 2026 – 2:00 PM (non-military time)

const express = require("express");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");

const app = express();
app.use(express.json());

// =======================
// In-Memory MVP Storage
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
// Health Check
// =======================

app.get("/", (req, res) => {
  res.json({
    status: "ProofDeed backend running",
    time: new Date().toLocaleString()
  });
});

// =======================
// Proof Endpoints
// =======================

// Create Proof
app.post("/proofs", (req, res) => {
  const { data, metadata } = req.body;

  if (!data) {
    return res.status(400).json({ error: "Missing data" });
  }

  const id = uuidv4();
  const timestamp = new Date().toISOString();
  const hash = generateHash(data + timestamp);

  const proof = {
    id,
    data,
    metadata: metadata || {},
    hash,
    timestamp
  };

  proofs.push(proof);

  res.json(proof);
});

// Get All Proofs
app.get("/proofs", (req, res) => {
  res.json({
    count: proofs.length,
    proofs
  });
});

// =======================
// Affiliate MVP
// =======================

// Register Affiliate
app.post("/affiliates", (req, res) => {
  const { name } = req.body;

  if (!name) {
    return res.status(400).json({ error: "Affiliate name required" });
  }

  const affiliate = {
    id: uuidv4(),
    name,
    created: new Date().toISOString()
  };

  affiliates.push(affiliate);

  res.json(affiliate);
});

// Get Affiliates
app.get("/affiliates", (req, res) => {
  res.json({
    count: affiliates.length,
    affiliates
  });
});

// =======================
// Server Boot
// =======================

const PORT = process.env.PORT || 8080;

app.listen(PORT, () => {
  console.log(`ProofDeed backend running on port ${PORT}`);
});
