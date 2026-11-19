-- Local-test seed data for the DoH worker battery (applied AFTER migrations/0002).
-- Covers: 0.0.0.0/8 private, 1.0.0.0/8 AU, 1.1.1.0/24 US, 8.8.8.0/24 US,
-- 10.0.0.0/8 private, 23.0.0.0/8 US, 96.0.0.0/8 US, 104.16.0.0/12 US,
-- 198.18.0.0/15 private, 223.5.5.0/24 CN; IPv6 default/2001:db8::/32/2606:4700::/32.
INSERT INTO merged_ipv4_data (network_start,country_iso_code) VALUES
 (0,'private'),
 (16777216,'AU'),
 (16843008,'US'),
 (134744064,'US'),
 (167772160,'private'),
 (385875968,'US'),
 (1610612736,'US'),
 (1745879040,'US'),
 (3323068416,'private'),
 (3741648128,'CN');
INSERT INTO merged_ipv6_data (network_start,country_iso_code) VALUES
 ('00000000000000000000000000000000','private'),
 ('20010db8000000000000000000000000','DE'),
 ('26064700000000000000000000000000','US');