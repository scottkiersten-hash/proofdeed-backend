const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

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

  proofs.push(proof);
  res.json(proof);
});

// Proof history
app.get("/proofs", (req, res) => {
  res.json(proofs);
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`ProofDeed backend running on port ${PORT}`);
});
