const express = require("express");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");

const app = express();
app.use(express.json());

// =======================
// In-memory storage (MVP)
// =======================

const proofs = [];
const affiliates = [];

// =======================
// Helpers
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

// Get all proofs
app.get("/proofs", (req, res) => {
  res.json({
    count: proofs.length,
    proofs
  });
});

// Create proof
app.post("/proofs", (req, res) => {
  const { data, metadata } = req.body;

  if (!d
