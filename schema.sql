-- ProofDeed Database Schema
-- Run this to initialize a fresh database or for disaster recovery.
-- All statements use IF NOT EXISTS so it is safe to re-run.
--
-- Regenerated 2026-08-12 by extracting every CREATE TABLE / ALTER TABLE /
-- CREATE INDEX statement actually present in server.js, since the app
-- self-migrates on every boot and this file had drifted out of sync with
-- the real production schema (missing columns like merkle_root, batch_id,
-- and several tables entirely). Tables are ordered so foreign keys resolve
-- on a clean run -- do not re-sort alphabetically.

-- ============================================================
-- Foundational tables (not created by server.js at runtime --
-- these must exist before the app's self-migration can run)
-- ============================================================

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

CREATE TABLE IF NOT EXISTS certifications (
  id                SERIAL PRIMARY KEY,
  certification_id  TEXT UNIQUE NOT NULL,
  hash              TEXT NOT NULL,
  polygon_tx        TEXT,
  user_id           INTEGER REFERENCES users(id) ON DELETE SET NULL,
  document_data     TEXT,
  created_at        TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS magic_links (
  id          SERIAL PRIMARY KEY,
  email       TEXT NOT NULL,
  token       TEXT UNIQUE NOT NULL,
  used        BOOLEAN DEFAULT FALSE,
  expires_at  TIMESTAMPTZ NOT NULL,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

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

CREATE TABLE IF NOT EXISTS contact_submissions (
  id            SERIAL PRIMARY KEY,
  name          TEXT NOT NULL,
  email         TEXT NOT NULL,
  company       TEXT,
  notes         TEXT,
  request_type  TEXT DEFAULT 'contact',
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================
-- Tables created by server.js at runtime bootstrap
-- (extracted verbatim; kept in dependency-safe order)
-- ============================================================

CREATE TABLE IF NOT EXISTS compliance_tokens (
  id SERIAL PRIMARY KEY,
  token TEXT UNIQUE NOT NULL,
  used BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  expires_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS domain_reputation (
  domain         TEXT PRIMARY KEY,
  bounce_count   INT NOT NULL DEFAULT 0,
  deliver_count  INT NOT NULL DEFAULT 0,
  is_catch_all   BOOLEAN NOT NULL DEFAULT false,
  suppressed     BOOLEAN NOT NULL DEFAULT false,
  last_seen      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS health_streak (
  name TEXT PRIMARY KEY,
  streak INT NOT NULL DEFAULT 0,
  last_alert_sent BIGINT DEFAULT 0
);

CREATE TABLE IF NOT EXISTS lead_engine_state (
  key        TEXT PRIMARY KEY,
  value      TEXT,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS outreach_contacts (
  id              SERIAL PRIMARY KEY,
  name            TEXT NOT NULL,
  email           TEXT UNIQUE NOT NULL,
  company         TEXT,
  title           TEXT,
  industry        TEXT,
  county          TEXT,
  state           TEXT,
  status          TEXT DEFAULT 'pending',
  notes           TEXT,
  first_sent_at   TIMESTAMPTZ,
  last_contact_at TIMESTAMPTZ,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS certification_events (
  id                SERIAL PRIMARY KEY,
  certification_id  TEXT NOT NULL,
  event_type        TEXT NOT NULL,
  event_label       TEXT,
  actor             TEXT,
  metadata          JSONB DEFAULT '{}',
  occurred_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS batches (
  id               SERIAL PRIMARY KEY,
  batch_id         TEXT UNIQUE NOT NULL,
  email            TEXT NOT NULL,
  status           TEXT DEFAULT 'processing',
  total            INTEGER DEFAULT 0,
  processed        INTEGER DEFAULT 0,
  failed           INTEGER DEFAULT 0,
  webhook_notified BOOLEAN DEFAULT FALSE,
  created_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS resellers (
  id              SERIAL PRIMARY KEY,
  reseller_id     TEXT UNIQUE NOT NULL,
  slug            TEXT UNIQUE NOT NULL,
  company_name    TEXT NOT NULL,
  contact_email   TEXT NOT NULL,
  api_key         TEXT UNIQUE NOT NULL,
  commission_rate NUMERIC(5,2) NOT NULL DEFAULT 20.00,
  brand_color     TEXT NOT NULL DEFAULT '#2563eb',
  brand_logo_url  TEXT,
  active          BOOLEAN NOT NULL DEFAULT true,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS trust_entities (
  id          SERIAL PRIMARY KEY,
  entity_id   TEXT UNIQUE NOT NULL,
  entity_type TEXT NOT NULL CHECK (entity_type IN ('organization','person','asset','record','event')),
  name        TEXT NOT NULL,
  subtype     TEXT,
  metadata    JSONB DEFAULT '{}',
  created_by  TEXT,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS trust_ids (
  id              SERIAL PRIMARY KEY,
  trust_id        TEXT UNIQUE NOT NULL,
  entity_type     TEXT NOT NULL,
  entity_name     TEXT NOT NULL,
  entity_email    TEXT,
  entity_org      TEXT,
  metadata        JSONB NOT NULL DEFAULT '{}',
  record_count    INT NOT NULL DEFAULT 0,
  trust_score     INT NOT NULL DEFAULT 0,
  api_key_email   TEXT,
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS asset_passports (
  id              SERIAL PRIMARY KEY,
  passport_id     TEXT UNIQUE NOT NULL,
  asset_type      TEXT NOT NULL,
  asset_identifier TEXT NOT NULL,
  label           TEXT,
  owner_name      TEXT,
  owner_email     TEXT,
  fields          JSONB NOT NULL DEFAULT '{}',
  field_hashes    JSONB NOT NULL DEFAULT '{}',
  root_hash       TEXT,
  polygon_tx      TEXT,
  proof_id        TEXT,
  api_key_email   TEXT,
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS trust_analyses (
  id            SERIAL PRIMARY KEY,
  analysis_id   TEXT UNIQUE NOT NULL,
  proof_id      TEXT,
  passport_id   TEXT,
  trust_id_ref  TEXT,
  risk_level    TEXT NOT NULL DEFAULT 'unknown',
  confidence    INTEGER NOT NULL DEFAULT 0,
  summary       TEXT,
  recommendation TEXT,
  findings      JSONB NOT NULL DEFAULT '[]',
  raw_input     JSONB NOT NULL DEFAULT '{}',
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- Depends on outreach_contacts
CREATE TABLE IF NOT EXISTS affiliates (
  id SERIAL PRIMARY KEY,
  contact_id INTEGER REFERENCES outreach_contacts(id) ON DELETE SET NULL,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  company TEXT,
  referral_code TEXT UNIQUE NOT NULL,
  commission_rate NUMERIC(5,2) DEFAULT 20.00,
  commission_type TEXT DEFAULT 'percentage',
  flat_amount NUMERIC(10,2),
  payout_method TEXT DEFAULT 'manual',
  payout_email TEXT,
  status TEXT DEFAULT 'active',
  notes TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Depends on outreach_contacts
CREATE TABLE IF NOT EXISTS inbound_emails (
  id              SERIAL PRIMARY KEY,
  message_id      TEXT UNIQUE,
  thread_id       TEXT,
  contact_id      INTEGER REFERENCES outreach_contacts(id) ON DELETE SET NULL,
  from_email      TEXT NOT NULL,
  from_name       TEXT,
  to_email        TEXT,
  subject         TEXT,
  body_text       TEXT,
  body_html       TEXT,
  intent          TEXT DEFAULT 'unknown',
  sentiment       TEXT DEFAULT 'neutral',
  suggested_reply TEXT,
  auto_replied    BOOLEAN DEFAULT false,
  requires_human  BOOLEAN DEFAULT true,
  is_read         BOOLEAN DEFAULT false,
  received_at     TIMESTAMPTZ DEFAULT NOW()
);

-- Depends on outreach_contacts
CREATE TABLE IF NOT EXISTS outreach_events (
  id              SERIAL PRIMARY KEY,
  contact_id      INTEGER REFERENCES outreach_contacts(id) ON DELETE CASCADE,
  event_type      TEXT NOT NULL,
  event_source    TEXT DEFAULT 'resend',
  resend_event_id TEXT UNIQUE,
  metadata        JSONB,
  occurred_at     TIMESTAMPTZ DEFAULT NOW(),
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Depends on trust_ids
CREATE TABLE IF NOT EXISTS trust_id_records (
  id            SERIAL PRIMARY KEY,
  trust_id      TEXT NOT NULL REFERENCES trust_ids(trust_id) ON DELETE CASCADE,
  record_type   TEXT NOT NULL,
  record_label  TEXT,
  proof_id      TEXT,
  passport_id   TEXT,
  root_hash     TEXT,
  polygon_tx    TEXT,
  fields        JSONB NOT NULL DEFAULT '{}',
  field_hashes  JSONB NOT NULL DEFAULT '{}',
  issued_at     TIMESTAMPTZ DEFAULT NOW()
);

-- Depends on trust_entities
CREATE TABLE IF NOT EXISTS trust_relationships (
  id                SERIAL PRIMARY KEY,
  certification_id  TEXT NOT NULL,
  entity_id         TEXT NOT NULL REFERENCES trust_entities(entity_id) ON DELETE CASCADE,
  relationship_type TEXT DEFAULT 'related_to',
  created_by        TEXT,
  created_at        TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(certification_id, entity_id)
);

-- Depends on affiliates
CREATE TABLE IF NOT EXISTS affiliate_payouts (
  id SERIAL PRIMARY KEY,
  affiliate_id INTEGER REFERENCES affiliates(id) ON DELETE CASCADE,
  amount NUMERIC(10,2) NOT NULL,
  payout_method TEXT DEFAULT 'manual',
  reference TEXT,
  status TEXT DEFAULT 'pending',
  notes TEXT,
  paid_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Depends on affiliates, users
CREATE TABLE IF NOT EXISTS affiliate_referrals (
  id SERIAL PRIMARY KEY,
  affiliate_id INTEGER REFERENCES affiliates(id) ON DELETE CASCADE,
  referred_email TEXT,
  referred_name TEXT,
  referred_company TEXT,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  referral_code TEXT,
  status TEXT DEFAULT 'clicked',
  plan TEXT,
  mrr NUMERIC(10,2) DEFAULT 0,
  commission_amount NUMERIC(10,2) DEFAULT 0,
  commission_status TEXT DEFAULT 'pending',
  converted_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Depends on asset_passports
CREATE TABLE IF NOT EXISTS asset_passport_events (
  id            SERIAL PRIMARY KEY,
  passport_id   TEXT NOT NULL REFERENCES asset_passports(passport_id) ON DELETE CASCADE,
  event_type    TEXT NOT NULL,
  event_label   TEXT,
  fields        JSONB NOT NULL DEFAULT '{}',
  field_hashes  JSONB NOT NULL DEFAULT '{}',
  root_hash     TEXT,
  polygon_tx    TEXT,
  proof_id      TEXT,
  occurred_at   TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================
-- Column migrations (server.js runs these as ALTER TABLE ...
-- ADD COLUMN IF NOT EXISTS on every boot -- extracted verbatim)
-- ============================================================

ALTER TABLE affiliates ADD COLUMN IF NOT EXISTS brand_color TEXT DEFAULT '#1a3a8e';
ALTER TABLE affiliates ADD COLUMN IF NOT EXISTS brand_logo_url TEXT;
ALTER TABLE affiliates ADD COLUMN IF NOT EXISTS brand_name TEXT;
ALTER TABLE affiliates ADD COLUMN IF NOT EXISTS brand_tagline TEXT;
ALTER TABLE affiliates ADD COLUMN IF NOT EXISTS brand_website TEXT;
ALTER TABLE affiliates ADD COLUMN IF NOT EXISTS white_label_enabled BOOLEAN DEFAULT FALSE;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS contract_notes TEXT;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS custom_price_per_cert NUMERIC(10,4);
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS notified_100 BOOLEAN DEFAULT FALSE;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS notified_80 BOOLEAN DEFAULT FALSE;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS organization_name TEXT;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS pilot_expires_at TIMESTAMPTZ;
ALTER TABLE batches ADD COLUMN IF NOT EXISTS merkle_root TEXT;
ALTER TABLE batches ADD COLUMN IF NOT EXISTS polygon_tx TEXT;
ALTER TABLE certifications ADD COLUMN IF NOT EXISTS ai_provenance TEXT CHECK (ai_provenance IN ('human', 'ai_assisted', 'ai_generated'));
ALTER TABLE certifications ADD COLUMN IF NOT EXISTS api_key_email TEXT;
ALTER TABLE certifications ADD COLUMN IF NOT EXISTS batch_id TEXT;
ALTER TABLE certifications ADD COLUMN IF NOT EXISTS forensic_analyzed_at TIMESTAMPTZ;
ALTER TABLE certifications ADD COLUMN IF NOT EXISTS forensic_anomalies JSONB;
ALTER TABLE certifications ADD COLUMN IF NOT EXISTS forensic_assessment TEXT CHECK (forensic_assessment IN ('clean', 'low', 'moderate', 'high'));
ALTER TABLE certifications ADD COLUMN IF NOT EXISTS forensic_authoring_software TEXT;
ALTER TABLE certifications ADD COLUMN IF NOT EXISTS forensic_declared_created_at TIMESTAMPTZ;
ALTER TABLE certifications ADD COLUMN IF NOT EXISTS forensic_declared_modified_at TIMESTAMPTZ;
ALTER TABLE certifications ADD COLUMN IF NOT EXISTS forensic_file_type TEXT;
ALTER TABLE certifications ADD COLUMN IF NOT EXISTS forensic_pdf_version_layers INTEGER;
ALTER TABLE certifications ADD COLUMN IF NOT EXISTS forensic_post_creation_edits INTEGER;
ALTER TABLE certifications ADD COLUMN IF NOT EXISTS forensic_total_editing_minutes INTEGER;
ALTER TABLE certifications ADD COLUMN IF NOT EXISTS ip_address TEXT;
ALTER TABLE certifications ADD COLUMN IF NOT EXISTS label TEXT;
ALTER TABLE certifications ADD COLUMN IF NOT EXISTS merkle_proof JSONB;
ALTER TABLE certifications ADD COLUMN IF NOT EXISTS merkle_root TEXT;
ALTER TABLE outreach_contacts ADD COLUMN IF NOT EXISTS auto_replied BOOLEAN DEFAULT false;
ALTER TABLE outreach_contacts ADD COLUMN IF NOT EXISTS intent TEXT DEFAULT 'unknown';
ALTER TABLE outreach_contacts ADD COLUMN IF NOT EXISTS last_inbound_at TIMESTAMPTZ;
ALTER TABLE outreach_contacts ADD COLUMN IF NOT EXISTS opened_count INTEGER DEFAULT 0;
ALTER TABLE outreach_contacts ADD COLUMN IF NOT EXISTS pain_status TEXT DEFAULT 'unaware';
ALTER TABLE outreach_contacts ADD COLUMN IF NOT EXISTS pipeline_stage TEXT DEFAULT 'contacted';
ALTER TABLE outreach_contacts ADD COLUMN IF NOT EXISTS priority_score INTEGER DEFAULT 0;
ALTER TABLE outreach_contacts ADD COLUMN IF NOT EXISTS reply_to_tag TEXT UNIQUE;
ALTER TABLE outreach_contacts ADD COLUMN IF NOT EXISTS requires_human BOOLEAN DEFAULT false;
ALTER TABLE outreach_contacts ADD COLUMN IF NOT EXISTS resend_message_id TEXT;
ALTER TABLE outreach_contacts ADD COLUMN IF NOT EXISTS sentiment TEXT DEFAULT 'neutral';
ALTER TABLE outreach_contacts ADD COLUMN IF NOT EXISTS tier TEXT DEFAULT 'primary';
ALTER TABLE outreach_contacts ADD COLUMN IF NOT EXISTS use_case TEXT;

-- ============================================================
-- Indexes
-- ============================================================

CREATE INDEX IF NOT EXISTS idx_users_email                        ON users(email);
CREATE INDEX IF NOT EXISTS idx_magic_links_token                   ON magic_links(token);
CREATE INDEX IF NOT EXISTS idx_api_keys_key                        ON api_keys(api_key);
CREATE INDEX IF NOT EXISTS idx_certifications_hash                 ON certifications(hash);
CREATE INDEX IF NOT EXISTS idx_certifications_user_id              ON certifications(user_id);
CREATE INDEX IF NOT EXISTS idx_certifications_batch_id             ON certifications(batch_id);
CREATE INDEX IF NOT EXISTS idx_batches_batch_id                    ON batches(batch_id);
CREATE INDEX IF NOT EXISTS idx_certification_events_cert           ON certification_events(certification_id);
CREATE INDEX IF NOT EXISTS idx_certification_events_occurred       ON certification_events(occurred_at);
CREATE INDEX IF NOT EXISTS idx_asset_passports_id                  ON asset_passports(passport_id);
CREATE INDEX IF NOT EXISTS idx_asset_passports_identifier          ON asset_passports(asset_identifier);
CREATE INDEX IF NOT EXISTS idx_asset_passport_events_passport      ON asset_passport_events(passport_id);
CREATE INDEX IF NOT EXISTS idx_trust_entities_type                 ON trust_entities(entity_type);
CREATE INDEX IF NOT EXISTS idx_trust_relationships_cert            ON trust_relationships(certification_id);
CREATE INDEX IF NOT EXISTS idx_trust_relationships_entity          ON trust_relationships(entity_id);
CREATE INDEX IF NOT EXISTS idx_trust_ids_id                        ON trust_ids(trust_id);
CREATE INDEX IF NOT EXISTS idx_trust_ids_email                     ON trust_ids(entity_email);
CREATE INDEX IF NOT EXISTS idx_trust_id_records_trust_id           ON trust_id_records(trust_id);
CREATE INDEX IF NOT EXISTS idx_trust_analyses_id                   ON trust_analyses(analysis_id);
CREATE INDEX IF NOT EXISTS idx_trust_analyses_proof                ON trust_analyses(proof_id);
CREATE INDEX IF NOT EXISTS idx_resellers_slug                      ON resellers(slug);
CREATE INDEX IF NOT EXISTS idx_resellers_api_key                   ON resellers(api_key);
CREATE INDEX IF NOT EXISTS idx_inbound_emails_contact               ON inbound_emails(contact_id);
CREATE INDEX IF NOT EXISTS idx_inbound_emails_from                  ON inbound_emails(from_email);
CREATE INDEX IF NOT EXISTS idx_inbound_emails_thread                ON inbound_emails(thread_id);
CREATE INDEX IF NOT EXISTS idx_inbound_emails_received               ON inbound_emails(received_at DESC);

-- ============================================================
-- Unused / vestigial schema -- defined here (and may physically exist
-- in the production database if this file was ever run) but NOT
-- written to or read from anywhere in server.js as of this writing.
-- "Version History" / "Living Digital Records" pricing features are
-- NOT backed by these tables or by anything else in the codebase.
-- Do not assume record_versions/record_events are populated.
-- ============================================================

CREATE TABLE IF NOT EXISTS trust_records (
  id               SERIAL PRIMARY KEY,
  trust_id         TEXT UNIQUE NOT NULL,
  record_type      TEXT NOT NULL DEFAULT 'document',
  status           TEXT NOT NULL DEFAULT 'active',
  hash             TEXT NOT NULL,
  polygon_tx       TEXT,
  user_id          INTEGER REFERENCES users(id) ON DELETE SET NULL,
  issuer_name      TEXT,
  issuer_email     TEXT,
  owner_name       TEXT,
  owner_email      TEXT,
  document_data    TEXT,
  visibility       TEXT NOT NULL DEFAULT 'public',
  current_version  INTEGER NOT NULL DEFAULT 1,
  expires_at       TIMESTAMPTZ,
  created_at       TIMESTAMPTZ DEFAULT NOW(),
  updated_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS record_versions (
  id              SERIAL PRIMARY KEY,
  trust_record_id INTEGER NOT NULL REFERENCES trust_records(id) ON DELETE CASCADE,
  version_number  INTEGER NOT NULL,
  hash            TEXT NOT NULL,
  polygon_tx      TEXT,
  document_data   TEXT,
  notes           TEXT,
  created_by      TEXT,
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (trust_record_id, version_number)
);

CREATE TABLE IF NOT EXISTS record_events (
  id              SERIAL PRIMARY KEY,
  trust_record_id INTEGER NOT NULL REFERENCES trust_records(id) ON DELETE CASCADE,
  event_type      TEXT NOT NULL,
  actor           TEXT,
  metadata        JSONB,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_trust_records_trust_id      ON trust_records(trust_id);
CREATE INDEX IF NOT EXISTS idx_trust_records_user_id       ON trust_records(user_id);
CREATE INDEX IF NOT EXISTS idx_trust_records_hash          ON trust_records(hash);
CREATE INDEX IF NOT EXISTS idx_trust_records_status        ON trust_records(status);
CREATE INDEX IF NOT EXISTS idx_record_versions_record_id   ON record_versions(trust_record_id);
CREATE INDEX IF NOT EXISTS idx_record_events_record_id     ON record_events(trust_record_id);
CREATE INDEX IF NOT EXISTS idx_record_events_type          ON record_events(event_type);
