const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

// In-memory proof storage (temporary)
const proofs = [];

// Health check
app.get("/", (req, res) => {
  res.json({ status: "ProofDeed backend running" });
});

// Create proof
app.post("/create-proof", (req, res) => {
  const { documentHash } = req.body;

  if (!documentHash) {
    return res.status(400).json({ error: "Document hash required" });
  }

  const proof = {
    proofId: crypto.randomUUID(),
    documentHash,
    timestamp: new Date().toISOString(),
    verification: "Document existed at this timestamp"
  };

  proofs.unshift(proof);
  proofs.splice(10); // keep last 10 proofs only

  res.json(proof);
});

// Get proof history
app.get("/proof-history", (req, res) => {
  res.json(proofs);
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`ProofDeed backend running on port ${PORT}`);
});
