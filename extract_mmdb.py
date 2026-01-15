#!/usr/bin/env python3
"""
Extract IPv4 and IPv6 data from Country.mmdb (Loyalsoldier format).
Outputs CSV files compatible with D1 import.
"""

import argparse
import csv
import os
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


def get_country_code(data):
    """Extract country ISO code from MMDB data record."""
    if not data:
        return None
    if 'country' in data and 'iso_code' in data['country']:
        return data['country']['iso_code']
    if 'registered_country' in data and 'iso_code' in data['registered_country']:
        return data['registered_country']['iso_code']
    return None


def process_network(network, country_code):
    """Process a single network entry and return record dict."""
    cidr = str(network)
    is_ipv6 = network.version != 4
    network_start = cidr_to_network_start(cidr, is_ipv6=is_ipv6)
    return {
        'network': cidr,
        'network_start': network_start,
        'country_iso_code': country_code
    }


def extract_mmdb(mmdb_path: str, ipv4_output: str, ipv6_output: str) -> None:
    """
    Read Country.mmdb and export to two CSV files.
    
    IPv4 CSV: network,network_start,country_iso_code
    IPv6 CSV: network,network_start,country_iso_code
    """
    print(f"Opening {mmdb_path}...")
    
    with maxminddb.open_database(mmdb_path) as reader:
        ipv4_records = []
        ipv6_records = []
        processed = 0
        
        for network, data in reader:
            processed += 1
            if processed % 50000 == 0:
                print(f"  Processed {processed} networks...")
            
            country_code = get_country_code(data)
            if not country_code:
                continue
            
            record = process_network(network, country_code)
            if network.version == 4:
                ipv4_records.append(record)
            else:
                ipv6_records.append(record)
        
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


def validate_inputs(mmdb_path: str, ipv4_output: str, ipv6_output: str) -> None:
    """Validate input parameters."""
    if not os.path.isfile(mmdb_path):
        raise FileNotFoundError(f"MMDB file not found: {mmdb_path}")
    
    for output_path in [ipv4_output, ipv6_output]:
        output_dir = os.path.dirname(output_path) or '.'
        if not os.path.isdir(output_dir):
            raise ValueError(f"Output directory does not exist: {output_dir}")
        if not os.access(output_dir, os.W_OK):
            raise PermissionError(f"No write permission to directory: {output_dir}")


def main():
    """Main entry point with argument parsing and validation."""
    parser = argparse.ArgumentParser(
        description='Extract IPv4 and IPv6 data from Country.mmdb (Loyalsoldier format)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python extract_mmdb.py Country.mmdb
  python extract_mmdb.py Country.mmdb custom_ipv4.csv custom_ipv6.csv
        '''
    )
    
    parser.add_argument(
        'mmdb_path',
        help='Path to the Country.mmdb file'
    )
    
    parser.add_argument(
        'ipv4_output',
        nargs='?',
        default='blocks_ipv4.csv',
        help='Output path for IPv4 CSV file (default: blocks_ipv4.csv)'
    )
    
    parser.add_argument(
        'ipv6_output',
        nargs='?',
        default='blocks_ipv6.csv',
        help='Output path for IPv6 CSV file (default: blocks_ipv6.csv)'
    )
    
    args = parser.parse_args()
    
    try:
        validate_inputs(args.mmdb_path, args.ipv4_output, args.ipv6_output)
        extract_mmdb(args.mmdb_path, args.ipv4_output, args.ipv6_output)
    except (FileNotFoundError, ValueError, PermissionError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()

