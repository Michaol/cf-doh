#!/usr/bin/env python3
"""
Extract IPv4 and IPv6 data from Country.mmdb (Loyalsoldier format).
Outputs CSV files compatible with D1 import.
"""

import csv
import sys
import ipaddress

try:
    import maxminddb
except ImportError:
    print("Error: maxminddb library not found. Install with: pip install maxminddb")
    sys.exit(1)


def ip_to_int(ip_str: str) -> int:
    """Convert IPv4 address string to integer."""
    return int(ipaddress.IPv4Address(ip_str))


def ipv6_to_hex(ip_str: str) -> str:
    """Convert IPv6 address to 32-character hex string for D1 indexing."""
    return format(int(ipaddress.IPv6Address(ip_str)), '032x')


def cidr_to_network_start(cidr: str, is_ipv6: bool = False):
    """
    Extract network start from CIDR notation.
    Returns integer for IPv4, hex string for IPv6.
    """
    network = ipaddress.ip_network(cidr, strict=False)
    if is_ipv6:
        return ipv6_to_hex(str(network.network_address))
    else:
        return ip_to_int(str(network.network_address))


def extract_mmdb(mmdb_path: str, ipv4_output: str, ipv6_output: str):
    """
    Read Country.mmdb and export to two CSV files.
    
    IPv4 CSV: network,network_start,country_iso_code
    IPv6 CSV: network,network_start,country_iso_code
    """
    print(f"Opening {mmdb_path}...")
    
    with maxminddb.open_database(mmdb_path) as reader:
        ipv4_records = []
        ipv6_records = []
        
        for network, data in reader:
            # Extract country code
            country_code = None
            if data:
                # Try different paths to get country code
                if 'country' in data and 'iso_code' in data['country']:
                    country_code = data['country']['iso_code']
                elif 'registered_country' in data and 'iso_code' in data['registered_country']:
                    country_code = data['registered_country']['iso_code']
            
            if not country_code:
                continue
            
            cidr = str(network)
            
            # Determine if IPv4 or IPv6
            if network.version == 4:
                network_start = cidr_to_network_start(cidr, is_ipv6=False)
                ipv4_records.append({
                    'network': cidr,
                    'network_start': network_start,
                    'country_iso_code': country_code
                })
            else:
                network_start = cidr_to_network_start(cidr, is_ipv6=True)
                ipv6_records.append({
                    'network': cidr,
                    'network_start': network_start,
                    'country_iso_code': country_code
                })
        
        print(f"Extracted {len(ipv4_records)} IPv4 records, {len(ipv6_records)} IPv6 records")
        
        # Sort by network_start for efficient D1 queries
        ipv4_records.sort(key=lambda x: x['network_start'])
        ipv6_records.sort(key=lambda x: x['network_start'])
        
        # Write IPv4 CSV
        print(f"Writing {ipv4_output}...")
        with open(ipv4_output, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['network', 'network_start', 'country_iso_code'])
            writer.writeheader()
            writer.writerows(ipv4_records)
        
        # Write IPv6 CSV
        print(f"Writing {ipv6_output}...")
        with open(ipv6_output, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['network', 'network_start', 'country_iso_code'])
            writer.writeheader()
            writer.writerows(ipv6_records)
        
        print("Done!")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python extract_mmdb.py <Country.mmdb> [ipv4_output.csv] [ipv6_output.csv]")
        sys.exit(1)
    
    mmdb_path = sys.argv[1]
    ipv4_output = sys.argv[2] if len(sys.argv) > 2 else 'blocks_ipv4.csv'
    ipv6_output = sys.argv[3] if len(sys.argv) > 3 else 'blocks_ipv6.csv'
    
    extract_mmdb(mmdb_path, ipv4_output, ipv6_output)
