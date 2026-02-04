const proofLedger = [];
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");

const proofLedger = [];

function generateHash(data) {
  return crypto
    .createHash("sha256")
    .update(data)
    .digest("hex");
}
const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

const proofs = [];

// Health check
app.get("/", (req, res) => {
  res.json({ status: "ProofDeed backend running" });
});
// Get all proofs
app.get("/proofs", (req, res) => {
  res.json({
    count: proofs.length,
    proofs: proofs
  });
});

// Create proof
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

  res.json({
    message: "Proof created",
    proof
  });
});


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

  res.json({
    message: "Proof created",
    proof
  });
});


  if (!documentHash) {
    return res.status(400).json({ error: "Document hash required" });
  }

  const proof = {
    proofId: crypto.randomUUID(),
    documentHash,
    timestamp: new Date().toISOString(),
    verification: "Document existed at this timestamp"
  };

  proofs.push(proof);
  res.json(proof);
});

// Proof history
app.get("/proofs", (req, res) => {
  res.json(proofs);
});
// Create proof
app.post("/proofs", (req, res) => {
  const { data } = req.body;

  if (!data) {
    return res.status(400).json({ error: "Data is required" });
  }

  const hash = generateHash(data);

  const proof = {
    id: uuidv4(),
    data,
    hash,
    timestamp: new Date().toISOString()
  };

  proofs.push(proof);

  res.json({
    message: "Proof created",
    proof
  });
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`ProofDeed backend running on port ${PORT}`);
});
// Create asset
app.post("/assets", (req, res) => {
  const { title, type } = req.body;

  if (!title || !type) {
    return res.status(400).json({ error: "Title and type are required" });
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

  };

  assets.push(asset);

  // Auto-create first proof
  const proof = {
    id: uuidv4(),
    data: `Asset created: ${title}`,
    metadata: { assetId: asset.id },
    hash: generateHash(asset.id + asset.title),
    timestamp: new Date().toISOString()
  };

  proofs.push(proof);

  res.status(201).json({
    asset,
    proof
  });
});
// Get all assets
app.get("/assets", (req, res) => {
  res.json({
    count: assets.length,
    assets
  });
});
// Issue tokens to owner
app.post("/assets/:id/issue", (req, res) => {
  const { id } = req.params;
  const { owner, amount } = req.body;

  const asset = assets.find(a => a.id === id);

  if (!asset) return res.status(404).json({ error: "Asset not found" });

  if (asset.tokensIssued + amount > asset.tokenSupply) {
    return res.status(400).json({ error: "Exceeds token supply" });
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
