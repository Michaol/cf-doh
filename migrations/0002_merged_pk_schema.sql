-- Merged-GeoIP schema (Phase 2 of the convergence migration)
-- SINGLE SOURCE OF TRUTH for the geoip tables. Apply ONLY to a fresh database
-- (it drops existing tables). Worker queries are unchanged; both lookups hit
-- the primary-key B-tree directly (1 rows_read per lookup, 1 rows_written
-- per inserted row).
--
-- NO secondary indexes anywhere: every index re-adds +1 rows_written per row
-- (the old schema's idx_*_network_start doubled the weekly import to ~1.95M).

DROP TABLE IF EXISTS merged_ipv4_data;
DROP TABLE IF EXISTS merged_ipv6_data;
DROP TABLE IF EXISTS meta;

-- IPv4: INTEGER PRIMARY KEY is a rowid alias -> the table IS the B-tree keyed
-- by network_start. Explicit start 0 (0.0.0.0/8 -> 'private') is legal.
-- country values are NOT always 2-letter ISO codes: Loyalsoldier emits list
-- names ('private', 'tor', 'cloudflare', ...) -> deliberately no CHECK(length=2).
CREATE TABLE merged_ipv4_data (
    network_start    INTEGER NOT NULL PRIMARY KEY,
    country_iso_code TEXT    NOT NULL
);

-- IPv6: WITHOUT ROWID clusters rows by the TEXT PK. Keys are exactly 32
-- lowercase hex chars (format(int, '032x')), whose BINARY-collation order
-- equals numeric order -> `network_start <= ? ORDER BY network_start DESC
-- LIMIT 1` is a pure PK seek.
CREATE TABLE merged_ipv6_data (
    network_start    TEXT NOT NULL PRIMARY KEY CHECK (length(network_start) = 32),
    country_iso_code TEXT NOT NULL
) WITHOUT ROWID;

-- Provenance + convergence state: source_tag, sha256, applied_at, expected
-- counts/hashes, trickle-rebuild cursors. The version rows are always written
-- LAST in a delta apply, so a tag in meta implies the data is fully applied.
CREATE TABLE meta (
    key   TEXT NOT NULL PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;
