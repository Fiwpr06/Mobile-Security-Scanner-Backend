-- =============================================
-- V3__add_dangerous_domains_and_ingestion_metadata.sql
-- New tables for offline threat intelligence pipeline
-- =============================================

CREATE TABLE IF NOT EXISTS dangerous_domains (
    domain          VARCHAR(255) PRIMARY KEY,
    reputation_score INTEGER NOT NULL DEFAULT 0,
    malicious_url_count BIGINT NOT NULL DEFAULT 0,
    is_blocked      BOOLEAN NOT NULL DEFAULT FALSE,
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_dangerous_domains_reputation ON dangerous_domains(reputation_score DESC);
CREATE INDEX idx_dangerous_domains_last_seen  ON dangerous_domains(last_seen_at DESC);

-- Tracks which CSV threat feed files have been ingested to avoid re-processing
CREATE TABLE IF NOT EXISTS ingestion_metadata (
    filename      VARCHAR(512) PRIMARY KEY,
    checksum      VARCHAR(64)  NOT NULL,
    file_size     BIGINT       NOT NULL,
    last_modified TIMESTAMPTZ  NOT NULL,
    ingested_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
