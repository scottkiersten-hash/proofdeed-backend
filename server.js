const express = require("express");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 8080;

// =======================
// In-memory MVP storage
// =======================

const proofs = [];
const affiliates = [];
const assets = [];

// =======================
// Helpers
// =======================

function generateHash(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

// Friendly timestamp (non-military)
function timestamp() {
  return new Date().toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "numeric",
    hour12: true
  });
}

// =======================
// Health Check
// =======================

app.get("/", (req, res) => {
  res.json({
    status: "ProofDeed backend running",
    time: timestamp()
  });
});

// =======================
// Proofs
// =======================

app.get("/proofs", (req, res) => {
  res.json({ count: proofs.length, proofs });
});

app.post("/proofs", (req, res) => {
  const { data, metadata } = req.body;

  if (!data) {
    return res.status(400).json({ error: "Data required" });
  }

  const proof = {
    id: uuidv4(),
    data,
    metadata: metadata || {},
    hash: generateHash(data + JSON.stringify(metadata || {})),
    createdAt: timestamp()
  };

  proofs.push(proof);

  res.json(proof);
});

// =======================
// Assets
// =======================

app.post("/assets", (req, res) => {
  const { title, type } = req.body;

  if (!title || !type) {
    return res.status(400).json({ error: "Title and type required" });
  }

  const asset = {
    id: uuidv4(),
    title,
    type,
    status: "draft",
    createdAt: timestamp(),
    ownership: []
  };

  assets.push(asset);

  res.json(asset);
});

app.get("/assets", (req, res) => {
  res.json({ count: assets.length, assets });
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
    createdAt: timestamp()
  };

  affiliates.push(affiliate);

  res.json(affiliate);
});

app.get("/affiliates", (req, res) => {
  res.json({ count: affiliates.length, affiliates });
});

// =======================
// Start server
// =======================

app.listen(PORT, () => {
  console.log(`ProofDeed backend running on port ${PORT}`);
});
