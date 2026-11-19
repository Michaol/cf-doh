-- Local-test seed data for the DoH worker battery (applied AFTER migrations/0002).
-- Synthetic fixture: country values only matter where tests assert them
-- (223.5.5.0/24=CN for the dual-IP case; 23.0.0.0/8 + 96.0.0.0/8=US for
-- example.com answer ranking). Other ranges use varied plausible values.
INSERT INTO merged_ipv4_data (network_start,country_iso_code) VALUES -- NOSONAR plsql:S1192 — test fixture: country literals ARE the data, not code constants
 (0,'private'),
 (16777216,'AU'),
 (16843008,'AU'),
 (134744064,'US'),
 (167772160,'private'),
 (385875968,'US'),
 (1610612736,'US'),
 (1745879040,'CA'),
 (3323068416,'ZZ'),
 (3741648128,'CN');
INSERT INTO merged_ipv6_data (network_start,country_iso_code) VALUES -- NOSONAR plsql:S1192 — test fixture: country literals ARE the data, not code constants
 ('00000000000000000000000000000000','private'),
 ('20010db8000000000000000000000000','DE'),
 ('26064700000000000000000000000000','US');