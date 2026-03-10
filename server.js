import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import pkg from "pg";
import crypto from "crypto";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import OpenAI from "openai";
import { anchorToPolygon } from "./polygon.js";

dotenv.config();

const { Pool } = pkg;

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

app.use(
  cors({
    origin: process.env.FRONTEND_URL,
    credentials: true
  })
);

app.use(helmet());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});

app.use(limiter);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];

  if (!authHeader) {
    return res.sendStatus(401);
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);

    req.user = user;
    next();
  });
}

app.get("/api/health", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");
    res.json({ status: "ok", database: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/test-cert", async (req, res) => {
  try {
    console.log("Starting test certification...");

    const testDocument = "ProofDeed test document " + Date.now();
    console.log("Test document:", testDocument);

    const hash = crypto.createHash("sha256").update(testDocument).digest("hex");
    console.log("Generated hash:", hash);

    const polygonTx = await anchorToPolygon(hash);
    console.log("Polygon TX:", polygonTx);

    const certificationId = "PD-" + Date.now();

    const result = await pool.query(
      `INSERT INTO certifications 
      (certification_id, hash, polygon_tx, user_id, document_data) 
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *`,
      [
        certificationId,
        hash,
        polygonTx,
        0,
        JSON.stringify({
          test: true,
          document: testDocument
        })
      ]
    );

    console.log("Certification inserted:", result.rows[0]);

    res.json({
      success: true,
      certification: result.rows[0]
    });
  } catch (error) {
    console.error("Test certification failed:", error);

    res.status(500).json({
      success: false,
      error: error.message || "Unknown error"
    });
  }
});

app.post("/api/certify-document", authenticateToken, async (req, res) => {
  try {
    const { document } = req.body;

    if (!document) {
      return res.status(400).json({ error: "Document is required" });
    }

    const hash = crypto.createHash("sha256").update(document).digest("hex");

    const duplicateCheck = await pool.query(
      "SELECT * FROM certifications WHERE hash = $1",
      [hash]
    );

    if (duplicateCheck.rows.length > 0) {
      return res.json({
        message: "Document already certified",
        certification: duplicateCheck.rows[0]
      });
    }

    const polygonTx = await anchorToPolygon(hash);

    let extractedData = {};

    try {
      const aiResponse = await openai.chat.completions.create({
        model: "gpt-4o-mini",
        messages: [
          {
            role: "system",
            content: "Extract structured data from this document."
          },
          {
            role: "user",
            content: document
          }
        ]
      });

      extractedData = aiResponse.choices[0].message.content;
    } catch (aiError) {
      console.log("AI extraction failed, continuing...");
    }

    const certificationId = "PD-" + Date.now();

    const result = await pool.query(
      `INSERT INTO certifications 
      (certification_id, hash, polygon_tx, user_id, document_data) 
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *`,
      [
        certificationId,
        hash,
        polygonTx,
        req.user.id,
        JSON.stringify(extractedData)
      ]
    );

    res.json({
      success: true,
      certification: result.rows[0]
    });
  } catch (error) {
    console.error("Certification failed:", error);

    res.status(500).json({
      error: "Certification failed",
      details: error.message
    });
  }
});

app.get("/api/verify/:hash", async (req, res) => {
  try {
    const { hash } = req.params;

    const result = await pool.query(
      "SELECT * FROM certifications WHERE hash = $1",
      [hash]
    );

    if (result.rows.length === 0) {
      return res.json({
        verified: false
      });
    }

    res.json({
      verified: true,
      certification: result.rows[0]
    });
  } catch (error) {
    res.status(500).json({
      error: error.message
    });
  }
});

app.get("/api/certificate/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      "SELECT * FROM certifications WHERE certification_id = $1",
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: "Certificate not found"
      });
    }

    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({
      error: error.message
    });
  }
});

app.listen(port, () => {
  console.log(`ProofDeed backend running on port ${port}`);
});
