-- =============================================
-- V5__drop_security_snacks_table.sql
-- Remove legacy SecuritySnacks table replaced by dangerous_domains
-- =============================================

DROP TABLE IF EXISTS security_snacks_domains;
