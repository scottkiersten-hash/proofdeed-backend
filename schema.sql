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

-- Outreach CRM
CREATE TABLE IF NOT EXISTS outreach_contacts (
  id            SERIAL PRIMARY KEY,
  name          TEXT NOT NULL,
  email         TEXT,
  company       TEXT,
  title         TEXT,
  industry      TEXT,        -- 'government' | 'auto' | 'institutional'
  county        TEXT,
  state         TEXT,
  status        TEXT DEFAULT 'sent',  -- 'sent' | 'replied' | 'in_talks' | 'closed_won' | 'closed_lost' | 'unsubscribed'
  notes         TEXT,
  first_sent_at TIMESTAMPTZ,
  last_contact_at TIMESTAMPTZ,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_users_email              ON users(email);
CREATE INDEX IF NOT EXISTS idx_certifications_hash      ON certifications(hash);
CREATE INDEX IF NOT EXISTS idx_certifications_user_id   ON certifications(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key             ON api_keys(api_key);
CREATE INDEX IF NOT EXISTS idx_magic_links_token        ON magic_links(token);

-- ============================================================
-- Trust Infrastructure Platform — Core Objects
-- ============================================================

-- Trust Records (primary object — replaces certifications as the conceptual center)
-- Existing certifications rows can be migrated here; certifications table stays for now.
CREATE TABLE IF NOT EXISTS trust_records (
  id               SERIAL PRIMARY KEY,
  trust_id         TEXT UNIQUE NOT NULL,          -- human-readable: PD-XXXX-XXXX
  record_type      TEXT NOT NULL DEFAULT 'document',  -- document | asset | identity | contract | title | license | other
  status           TEXT NOT NULL DEFAULT 'active',    -- active | revoked | expired | pending
  hash             TEXT NOT NULL,                 -- SHA-256 of original document
  polygon_tx       TEXT,                          -- blockchain anchor tx hash
  user_id          INTEGER REFERENCES users(id) ON DELETE SET NULL,
  issuer_name      TEXT,
  issuer_email     TEXT,
  owner_name       TEXT,
  owner_email      TEXT,
  document_data    TEXT,                          -- base64 or metadata JSON
  visibility       TEXT NOT NULL DEFAULT 'public',   -- public | private | organization | government
  current_version  INTEGER NOT NULL DEFAULT 1,
  expires_at       TIMESTAMPTZ,                   -- null = never expires
  created_at       TIMESTAMPTZ DEFAULT NOW(),
  updated_at       TIMESTAMPTZ DEFAULT NOW()
);

-- Version history — each update creates a new snapshot; prior versions are immutable
CREATE TABLE IF NOT EXISTS record_versions (
  id              SERIAL PRIMARY KEY,
  trust_record_id INTEGER NOT NULL REFERENCES trust_records(id) ON DELETE CASCADE,
  version_number  INTEGER NOT NULL,
  hash            TEXT NOT NULL,
  polygon_tx      TEXT,
  document_data   TEXT,
  notes           TEXT,                           -- reason for update
  created_by      TEXT,                           -- email of who made the update
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (trust_record_id, version_number)
);

-- Audit trail — append-only log of every action on a Trust Record
CREATE TABLE IF NOT EXISTS record_events (
  id              SERIAL PRIMARY KEY,
  trust_record_id INTEGER NOT NULL REFERENCES trust_records(id) ON DELETE CASCADE,
  event_type      TEXT NOT NULL,                  -- created | updated | verified | viewed | shared | revoked | renewed | transferred
  actor           TEXT,                           -- email or 'anonymous' for public verifications
  metadata        JSONB,                          -- any additional context (IP, user agent, etc.)
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Trust Record indexes
CREATE INDEX IF NOT EXISTS idx_trust_records_trust_id      ON trust_records(trust_id);
CREATE INDEX IF NOT EXISTS idx_trust_records_user_id       ON trust_records(user_id);
CREATE INDEX IF NOT EXISTS idx_trust_records_hash          ON trust_records(hash);
CREATE INDEX IF NOT EXISTS idx_trust_records_status        ON trust_records(status);
CREATE INDEX IF NOT EXISTS idx_record_versions_record_id   ON record_versions(trust_record_id);
CREATE INDEX IF NOT EXISTS idx_record_events_record_id     ON record_events(trust_record_id);
CREATE INDEX IF NOT EXISTS idx_record_events_type          ON record_events(event_type);
