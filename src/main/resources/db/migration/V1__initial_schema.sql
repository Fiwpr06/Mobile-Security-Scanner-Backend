-- =============================================
-- V1__initial_schema.sql
-- Initial database schema for Mobile Security Scanner
-- =============================================

-- Devices table for device-based authentication
CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id VARCHAR(256) NOT NULL UNIQUE,
    platform VARCHAR(50),
    app_version VARCHAR(50),
    registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    scan_count BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX idx_devices_device_id ON devices(device_id);
CREATE INDEX idx_devices_registered_at ON devices(registered_at);

-- Scan results table
CREATE TABLE IF NOT EXISTS scan_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url TEXT NOT NULL,
    url_hash VARCHAR(64) NOT NULL,
    device_id VARCHAR(256) NOT NULL,
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    status VARCHAR(20) NOT NULL CHECK (status IN ('SAFE', 'SUSPICIOUS', 'DANGEROUS')),
    -- Google Safe Browsing fields
    google_safe_browsing_flagged BOOLEAN,
    google_threat_type TEXT,
    -- VirusTotal fields
    virus_total_malicious INTEGER,
    virus_total_suspicious INTEGER,
    virus_total_total_engines INTEGER,
    -- AbuseIPDB fields
    abuse_ipdb_confidence_score INTEGER,
    abuse_ipdb_country_code VARCHAR(10),
    -- Meta
    scan_time_ms BIGINT NOT NULL,
    scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_cached BOOLEAN NOT NULL DEFAULT FALSE,
    error_message TEXT
);

CREATE INDEX idx_scan_results_url_hash ON scan_results(url_hash);
CREATE INDEX idx_scan_results_device_id ON scan_results(device_id);
CREATE INDEX idx_scan_results_status ON scan_results(status);
CREATE INDEX idx_scan_results_scanned_at ON scan_results(scanned_at DESC);

-- Malicious URLs table (threat intelligence)
CREATE TABLE IF NOT EXISTS malicious_urls (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url TEXT NOT NULL,
    url_hash VARCHAR(64) NOT NULL UNIQUE,
    threat_category VARCHAR(100),
    detection_count BIGINT NOT NULL DEFAULT 1,
    last_detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    first_detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sources TEXT  -- JSON list of sources that flagged this URL
);

CREATE INDEX idx_malicious_urls_url_hash ON malicious_urls(url_hash);
CREATE INDEX idx_malicious_urls_detection_count ON malicious_urls(detection_count DESC);

-- False negative reports table
CREATE TABLE IF NOT EXISTS false_negative_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url TEXT NOT NULL,
    device_id VARCHAR(256) NOT NULL,
    original_status VARCHAR(20) NOT NULL,
    original_risk_score INTEGER NOT NULL DEFAULT 0,
    user_description TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'REVIEWED', 'CONFIRMED_THREAT', 'DISMISSED')),
    reported_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reviewed_at TIMESTAMPTZ,
    reviewer_notes TEXT
);

CREATE INDEX idx_reports_status ON false_negative_reports(status);
CREATE INDEX idx_reports_device_id ON false_negative_reports(device_id);
CREATE INDEX idx_reports_url ON false_negative_reports(url);
CREATE UNIQUE INDEX idx_reports_url_device ON false_negative_reports(url, device_id);
