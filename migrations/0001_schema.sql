-- GeoIP Database Schema (LEGACY - historical only; never applied by CI)
-- This migration creates the initial table structure for GeoIP data
-- Superseded by 0002_merged_pk_schema.sql (merged same-country runs,
-- primary-key layouts, no secondary indexes). Kept for migration history.

DROP TABLE IF EXISTS merged_ipv4_data;
DROP TABLE IF EXISTS merged_ipv6_data;

CREATE TABLE IF NOT EXISTS merged_ipv4_data (
    network_start INTEGER,
    country_iso_code TEXT,
    network TEXT
);

CREATE TABLE IF NOT EXISTS merged_ipv6_data (
    network_start TEXT,
    country_iso_code TEXT,
    network TEXT
);

CREATE INDEX IF NOT EXISTS idx_ipv4_network_start ON merged_ipv4_data (network_start);
CREATE INDEX IF NOT EXISTS idx_ipv6_network_start ON merged_ipv6_data (network_start);
