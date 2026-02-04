const express = require("express");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");

const app = express();
app.use(express.json());

const proofs = [];
const assets = [];
const affiliates = [];

function generateHash(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

// =======================
// Health
// =======================

app.get("/", (req, res) => {
  res.json({ status: "ProofDeed backend running" });
});

// =======================
// Proofs
// =======================

app.get("/proofs", (req, res) => {
  res.json(proofs);
});

app.post("/proofs", (req, res) => {
  const { data, metadata } = req.body;

  if (!data) return res.status(400).json({ error: "Data required" });

  const proof = {
    id: uuidv4(),
    data,
    metadata: metadata || {},
    hash: generateHash(data + JSON.stringify(metadata || {})),
    timestamp: new Date().toISOString()
  };

  proofs.push(proof);

  res.json(proof);
});

// =======================
// Assets
// =======================

app.post("/assets", (req, res) => {
  const { title, type } = req.body;

  if (!title || !type)
    return res.status(400).json({ error: "Title and type required" });

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

  const proof = {
    id: uuidv4(),
    data: `Asset created: ${title}`,
    metadata: { assetId: asset.id },
    hash: generateHash(asset.id),
    timestamp: new Date().toISOString()
  };

  proofs.push(proof);

  res.json({ asset, proof });
});

app.get("/assets", (req, res) => {
  res.json(assets);
});

// =======================
// Affiliates
// =======================

app.post("/affiliates/signup", (req, res) => {
  const { name, email } = req.body;

  if (!name || !email)
    return res.status(400).json({ error: "Name and email required" });

  const affiliate = {
    id: uuidv4(),
    name,
    email,
    referrals: 0,
    createdAt: new Date().toISOString()
  };

  affiliates.push(affiliate);

  res.json(affiliate);
});

app.get("/affiliates", (req, res) => {
  res.json(affiliates);
});

// =======================
// Start Server
// =======================

const PORT = process.env.PORT || 8080;

app.listen(PORT, () => {
  console.log(`ProofDeed backend running on ${PORT}`);
});
