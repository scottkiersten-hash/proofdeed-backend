const express = require("express");
const app = express();

app.use(express.json());

// Health check
app.get("/", (req, res) => {
  res.json({ status: "ProofDeed backend running" });
});

// Create proof endpoint (beta)
app.post("/create-proof", (req, res) => {
  const { documentHash } = req.body;

  if (!documentHash) {
    return res.status(400).json({ error: "Missing document hash" });
  }

  const timestamp = new Date().toISOString();

  res.json({
    message: "Proof created (beta)",
    documentHash,
    timestamp
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`ProofDeed backend running on port ${PORT}`);
});
