import pkg from "pg";
import dotenv from "dotenv";
dotenv.config();

const { Pool } = pkg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function setup() {
  console.log("Setting up ProofDeed database...");

  await pool.query(`
    CREATE TABLE IF NOT EXISTS certifications (
      certification_id TEXT PRIMARY KEY,
      hash TEXT NOT NULL,
      polygon_tx TEXT,
      created_at TIMESTAMP DEFAULT NOW(),
      document_data JSONB
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      stripe_customer_id TEXT,
      subscription_id TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_certifications_hash 
    ON certifications(hash);
  `);

  console.log("✅ Tables created successfully.");
  await pool.end();
}

setup().catch(console.error);
