const express = require("express");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");

const app = express();
app.use(express.json());

// In-memory stores
const proofs = [];
const assets = [];
const affiliates = [];

// Hash helper
function generateHash(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

// =======================
// Health Check
// =======================
app.get("/", (req, res) => {
  res.status(200).json({ status: "ProofDeed backend running" });
});

// =======================
// Proofs
// =======================
app.get("/proofs", (req, res) => {
  res.json({ count: proofs.length, proofs });
});

app.post("/proofs", (req, res) => {
  const { data, metadata } = req.body;

  if (!data) return res.status(400).json({ error: "Data is required" });

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
  res.json({ count: assets.length, assets });
});

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
    hash: generateHash(asset.id + asset.title),
    timestamp: new Date().toISOString()
  };

  proofs.push(proof);

  res.json({ asset, proof });
});

// =======================
// Issue Tokens
// =======================
app.post("/assets/:id/issue", (req, res) => {
  const { id } = req.params;
  const { owner, amount } = req.body;

  const asset = assets.find(a => a.id === id);
  if (!asset) return res.status(404).json({ error: "Asset not found" });

  asset.tokensIssued += amount;

  asset.ownership.push({
    owner,
    amount,
    timestamp: new Date().toISOString()
  });

  res.json(asset);
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

  res.json({ success: true, affiliate });
});

app.get("/affiliates", (req, res) => {
  res.json(affiliates);
});

// =======================
// START SERVER (IMPORTANT)
// =======================
const PORT = process.env.PORT || 8080;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`ProofDeed backend running on port ${PORT}`);
});
