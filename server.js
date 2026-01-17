import express from "express";

const app = express();
const PORT = process.env.PORT || 8080;

app.use(express.json());

app.get("/", (req, res) => {
  res.json({ status: "ProofDeed backend running" });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
