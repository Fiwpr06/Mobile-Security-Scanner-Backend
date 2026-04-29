CREATE TABLE security_snacks_domains (
    domain VARCHAR(255) PRIMARY KEY,
    added_at TIMESTAMP NOT NULL,
    last_seen_at TIMESTAMP NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX idx_security_snacks_last_seen ON security_snacks_domains (last_seen_at);
