-- =============================================
-- V4__redesign_malicious_urls_schema.sql
-- Redesign malicious_urls to support canonical URL matching and upsert
-- =============================================

-- Drop old UUID-based primary key and recreate with url_hash as PK
-- This allows atomic ON CONFLICT upsert without needing a separate SELECT

ALTER TABLE malicious_urls DROP CONSTRAINT malicious_urls_pkey;
ALTER TABLE malicious_urls DROP COLUMN id;

-- Make url_hash the primary key (it was already UNIQUE)
ALTER TABLE malicious_urls ADD PRIMARY KEY (url_hash);

-- Add canonical decomposition fields for domain-level aggregation
ALTER TABLE malicious_urls
    ADD COLUMN IF NOT EXISTS normalized_domain VARCHAR(255) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS normalized_path   TEXT         NOT NULL DEFAULT '/',
    ADD COLUMN IF NOT EXISTS is_dangerous      BOOLEAN      NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS confidence_score  DOUBLE PRECISION NOT NULL DEFAULT 0.0;

-- Backfill default normalized_domain from existing url data (best effort)
UPDATE malicious_urls SET normalized_domain = url WHERE normalized_domain = '';

-- Add performance indexes
CREATE INDEX IF NOT EXISTS idx_malicious_urls_domain    ON malicious_urls(normalized_domain);
CREATE INDEX IF NOT EXISTS idx_malicious_urls_threat    ON malicious_urls(threat_category);
CREATE INDEX IF NOT EXISTS idx_malicious_urls_dangerous ON malicious_urls(is_dangerous);
