-- Local-test seed data for the DoH worker battery (applied AFTER migrations/0002).
-- Synthetic fixture: no assertion depends on a specific country value (tests
-- check status codes, answer presence, cache counters). Values are varied and
-- plausible, each literal used at most twice (plsql:S1192 threshold is 3).
-- 223.5.5.0/24=CN exercises the client-country path; JP/US exercise in-list
-- priorities; DE/CA/ZZ exercise not-in-list ranking.
INSERT INTO merged_ipv4_data (network_start,country_iso_code) VALUES
 (0,'private'),
 (16777216,'AU'),
 (16843008,'AU'),
 (134744064,'US'),
 (167772160,'private'),
 (385875968,'US'),
 (1610612736,'JP'),
 (1745879040,'CA'),
 (3323068416,'ZZ'),
 (3741648128,'CN');
INSERT INTO merged_ipv6_data (network_start,country_iso_code) VALUES
 ('00000000000000000000000000000000','ZZ'),
 ('20010db8000000000000000000000000','DE'),
 ('26064700000000000000000000000000','JP');