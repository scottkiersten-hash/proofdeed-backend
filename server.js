import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.json());

// Health check
app.get("/", (req, res) => {
  res.json({ status: "ProofDeed backend running" });
});

// Create proof endpoint
app.post("/create-proof", (req, res) => {
  const { documentHash } = req.body;

  if (!documentHash) {
    return res.status(400).json({ error: "Document hash required" });
  }

  const proof = {
    proofId: crypto.randomUUID(),
    documentHash,
    timestamp: new Date().toISOString(),
    verification:
      "This proof confirms the document existed at the timestamp shown."
  };

  res.json(proof);
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`ProofDeed backend running on port ${PORT}`);
});
