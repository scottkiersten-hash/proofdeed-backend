-- ProofDeed Database Schema
-- Run this to initialize a fresh database or for disaster recovery.
-- All statements use IF NOT EXISTS so it is safe to re-run.

-- Users
CREATE TABLE IF NOT EXISTS users (
  id                  SERIAL PRIMARY KEY,
  email               TEXT UNIQUE NOT NULL,
  stripe_customer_id  TEXT,
  subscription_id     TEXT,
  referral_code       TEXT UNIQUE,
  referred_by         TEXT,
  revenue_generated   INTEGER DEFAULT 0,
  created_at          TIMESTAMPTZ DEFAULT NOW()
);

-- Certifications
CREATE TABLE IF NOT EXISTS certifications (
  id                SERIAL PRIMARY KEY,
  certification_id  TEXT UNIQUE NOT NULL,
  hash              TEXT NOT NULL,
  polygon_tx        TEXT,
  user_id           INTEGER REFERENCES users(id) ON DELETE SET NULL,
  document_data     TEXT,
  created_at        TIMESTAMPTZ DEFAULT NOW()
);

-- Magic Links
CREATE TABLE IF NOT EXISTS magic_links (
  id          SERIAL PRIMARY KEY,
  email       TEXT NOT NULL,
  token       TEXT UNIQUE NOT NULL,
  used        BOOLEAN DEFAULT FALSE,
  expires_at  TIMESTAMPTZ NOT NULL,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- API Keys (Enterprise)
CREATE TABLE IF NOT EXISTS api_keys (
  id                          SERIAL PRIMARY KEY,
  email                       TEXT UNIQUE NOT NULL,
  api_key                     TEXT UNIQUE NOT NULL,
  plan                        TEXT DEFAULT 'enterprise',
  monthly_limit               INTEGER DEFAULT 1000,
  used_this_month             INTEGER DEFAULT 0,
  stripe_subscription_item_id TEXT,
  webhook_url                 TEXT,
  active                      BOOLEAN DEFAULT TRUE,
  created_at                  TIMESTAMPTZ DEFAULT NOW()
);

-- Contact / Affiliate Submissions
CREATE TABLE IF NOT EXISTS contact_submissions (
  id            SERIAL PRIMARY KEY,
  name          TEXT NOT NULL,
  email         TEXT NOT NULL,
  company       TEXT,
  notes         TEXT,
  request_type  TEXT DEFAULT 'contact',
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_users_email              ON users(email);
CREATE INDEX IF NOT EXISTS idx_certifications_hash      ON certifications(hash);
CREATE INDEX IF NOT EXISTS idx_certifications_user_id   ON certifications(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key             ON api_keys(api_key);
CREATE INDEX IF NOT EXISTS idx_magic_links_token        ON magic_links(token);
