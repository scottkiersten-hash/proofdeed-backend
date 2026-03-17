import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import pkg from "pg";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import OpenAI from "openai";

dotenv.config();

const { Pool } = pkg;

const app = express();
app.set("trust proxy", 1);

const PORT = process.env.PORT || 8080;

/* ---------------- Database ---------------- */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

/* ---------------- Normal Middleware ---------------- */

app.use(express.json({ limit: "5mb" }));

const configuredOrigins = [
  process.env.FRONTEND_URL,
  process.env.FRONTEND_URL_ALT,
  "https://proofdeed.com",
  "https://www.proofdeed.com"
]
  .filter(Boolean)
  .map((origin) => origin.trim());

const allowedOrigins = [...new Set(configuredOrigins)];

app.use(
  cors({
    origin(origin, callback) {

      if (!origin) {
        return callback(null, true);
      }

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error(`CORS blocked for origin: ${origin}`));
    },
    credentials: true
  })
);

app.use(helmet());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});

app.use(limiter);

/* ---------------- OpenAI ---------------- */

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

/* ---------------- Auth ---------------- */

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

/* ---------------- Root ---------------- */

app.get("/", (req, res) => {

  res.status(200).json({
    service: "proofdeed-backend",
    status: "ok",
    message: "Backend is running",
    frontend_url: process.env.FRONTEND_URL || "https://proofdeed.com",
    health_endpoint: "/api/health"
  });

});

/* ---------------- Health ---------------- */

app.get("/api/health", async (req, res) => {

  try {

    const result = await pool.query("SELECT NOW()");

    res.json({
      status: "ok",
      database: result.rows[0]
    });

  } catch (error) {

    res.status(500).json({
      status: "error",
      error: error.message
    });

  }

});

/* ---------------- Test Certification ---------------- */

app.get("/api/test-cert", async (req, res) => {

  try {

    const testDocument = "ProofDeed test document " + Date.now();

    const hash = crypto
      .createHash("sha256")
      .update(testDocument)
      .digest("hex");

    res.json({
      document: testDocument,
      hash
    });

  } catch (error) {

    res.status(500).json({
      error: error.message
    });

  }

});

/* ---------------- Start Server ---------------- */

app.listen(PORT, () => {

  console.log(`ProofDeed backend running on port ${PORT}`);

});
