const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

app.get("/", (req, res) => {
  res.json({ status: "ProofDeed backend running" });
});

app.post("/create-proof", (req, res) => {
  const documentHash = req.body.documentHash;

  if (!documentHash) {
    return res.status(400).json({ error: "Missing documentHash" });
  }

  res.json({
    proofId: crypto.randomUUID(),
    documentHash: documentHash,
    timestamp: new Date().toISOString(),
    verification: "Document existed at this timestamp"
  });
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log("ProofDeed backend running on port " + PORT);
});
