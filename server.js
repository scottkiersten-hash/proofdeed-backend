import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.json());

const proofs = []; // in-memory storage

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
app.get("/proof-history", (req, res) => {
  res.json(proofs);
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`ProofDeed backend running on port ${PORT}`);
});
