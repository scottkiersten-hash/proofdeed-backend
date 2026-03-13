 import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import pkg from "pg";
import crypto from "crypto";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import OpenAI from "openai";
import Stripe from "stripe";
import { anchorToPolygon } from "./polygon.js";

dotenv.config();

const { Pool } = pkg;

/* ---------------- Database ---------------- */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

/* ---------------- App ---------------- */

const app = express();
app.set("trust proxy", 1);
const port = process.env.PORT || 3000;

/* ---------------- Stripe ---------------- */

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
