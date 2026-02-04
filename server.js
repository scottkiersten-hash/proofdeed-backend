const express = require("express");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");

const app = express();
app.use(express.json());

// =======================
// In-memory storage (Phase 1)
// =======================

const proofs = [];
const assets = [];
const affiliates = [];

// =======================
// Utilities
// =======================

function generateHash(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

// =======================
// Health Check
// =======================

app.get("/", (req, res) => {
  res.json({ status: "ProofDeed backend running" });
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
// Assets
// =======================

app.get("/assets", (req, res) => {
  res.json({
    count: assets.length,
    assets
  });
});

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
    tokenSupply: 1000000,
    tokensIssued: 0,
    ownership: [],
    createdAt: new Date().toISOString()
  };

  assets.push(asset);

  // Auto-create proof
  const proof = {
    id: uuidv4(),
    data: `Asset created: ${title}`,
    metadata: { assetId: asset.id },
    hash: generateHash(asset.id + title),
    timestamp: new Date().toISOString()
  };

  proofs.push(proof);

  res.status(201).json({ asset, proof });
});

// Issue tokens

app.post("/assets/:id/issue", (req, res) => {
  const { id } = req.params;
  const { owner, amount } = req.body;

  const asset = assets.find(a => a.id === id);
  if (!asset) return res.status(404).json({ error: "Asset not found" });

  if (asset.tokensIssued + amount > asset.tokenSupply) {
    return res.status(400).json({ error: "Exceeds supply" });
  }

  asset.tokensIssued += amount;

  asset.ownership.push({
    owner,
    amount,
    timestamp: new Date().toISOString()
  });

  const proof = {
    id: uuidv4(),
    data: "Tokens issued",
    metadata: { assetId: id, owner, amount },
    hash: generateHash(id + owner + amount),
    timestamp: new Date().toISOString()
  };

  proofs.push(proof);

  res.json({ asset, proof });
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
// Server
// =======================

const PORT = process.env.PORT || 8080;

app.listen(PORT, () => {
  console.log(`ProofDeed backend running on port ${PORT}`);
});
