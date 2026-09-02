#!/usr/bin/env python3
"""
Build D1-bound GeoIP tables from Loyalsoldier Country.mmdb (Phase 2 tooling).

Replaces the raw per-CIDR dump (~974k rows) with merged same-country runs
(~500k rows or fewer). Merging is lossless for the worker's lookup query:

    SELECT country_iso_code FROM merged_ipvX_data
    WHERE network_start <= ?1 ORDER BY network_start DESC LIMIT 1

because only runs with the SAME country are combined: for every IP, the
country of the greatest run start <= IP is unchanged. Runs of equal country
separated by an unclassified gap are also merged — gap IPs resolved to that
same country before (via the earlier run) and still do afterwards.

Outputs (CSV, no header, sorted by network_start):
    blocks_ipv4_merged.csv: network_start(int),country_iso_code
    blocks_ipv6_merged.csv: network_start(32-hex lowercase),country_iso_code
    *.debug.csv (with --debug-output): adds network_end (CI-side only; the
    end column is never loaded into D1)

All invariants are asserted before writing; any failure exits non-zero and
writes nothing.
"""

import argparse
import csv
import ipaddress
import os
import sys

import maxminddb

from pathguard import validated_path


def get_country_code(data):
    """Extract country code from an MMDB record (same precedence as extract_mmdb.py)."""
    if not data:
        return None
    if 'country' in data and 'iso_code' in data['country']:
        return data['country']['iso_code']
    if 'registered_country' in data and 'iso_code' in data['registered_country']:
        return data['registered_country']['iso_code']
    return None


def extract_raw(mmdb_path):
    """Return (v4, v6) sorted lists of (start:int, end:int, country:str)."""
    v4, v6 = [], []
    with maxminddb.open_database(mmdb_path) as reader:
        for network, data in reader:
            country = get_country_code(data)
            if not country:
                continue
            net = ipaddress.ip_network(str(network), strict=False)
            row = (int(net.network_address), int(net.broadcast_address), country)
            (v4 if net.version == 4 else v6).append(row)
    v4.sort()
    v6.sort()
    return v4, v6


def assert_raw_sane(rows, label):
    prev_end = -1
    for s, e, c in rows:
        if s <= prev_end:
            raise AssertionError(f'{label}: overlapping or unsorted raw rows at start={s}')
        if e < s:
            raise AssertionError(f'{label}: end < start at start={s}')
        if not c:
            raise AssertionError(f'{label}: empty country at start={s}')
        prev_end = e


def merge_runs(rows):
    """Collapse maximal same-country runs (adjacent or gap-separated)."""
    merged = []
    cur = None  # [start, end, country]
    for s, e, c in rows:
        if cur is not None and cur[2] == c:
            cur[1] = e
        else:
            if cur is not None:
                merged.append((cur[0], cur[1], cur[2]))
            cur = [s, e, c]
    if cur is not None:
        merged.append((cur[0], cur[1], cur[2]))
    return merged


def assert_merged_sane(merged, label, is_v4, expect_count=None):
    if not merged:
        raise AssertionError(f'{label}: merged table is empty')
    prev_start = None
    limit = (1 << 32) if is_v4 else (1 << 128)
    for s, e, c in merged:
        if prev_start is not None and s <= prev_start:
            raise AssertionError(f'{label}: merged starts not strictly increasing at {s}')
        if not (0 <= s < limit) or e < s or e >= limit:
            raise AssertionError(f'{label}: range out of bounds at start={s} end={e}')
        if not c:
            raise AssertionError(f'{label}: empty country at start={s}')
        prev_start = s
    if is_v4 and merged[0][0] != 0:
        raise AssertionError(f'{label}: first IPv4 run must start at 0, got {merged[0][0]}')
    if expect_count is not None and not (0.8 * expect_count <= len(merged) <= 1.2 * expect_count):
        raise AssertionError(
            f'{label}: row count {len(merged)} deviates >20% from expected {expect_count}'
        )


def write_csv(path, merged, is_v4, debug_path=None):
    with open(validated_path(path), 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        for s, _e, c in merged:
            w.writerow([s if is_v4 else format(s, '032x'), c])
    if debug_path:
        with open(validated_path(debug_path), 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            for s, e, c in merged:
                if is_v4:
                    w.writerow([s, e, c])
                else:
                    w.writerow([format(s, '032x'), format(e, '032x'), c])


def main():
    p = argparse.ArgumentParser(description='Build merged GeoIP CSVs from Country.mmdb')
    p.add_argument('mmdb_path', help='path to Loyalsoldier Country.mmdb (tag-pinned)')
    p.add_argument('out_dir', nargs='?', default='tmp', help='output directory (default: tmp)')
    p.add_argument('--expect-v4-count', type=int, default=None,
                   help='previous build row count; abort if new count deviates >20%%')
    p.add_argument('--expect-v6-count', type=int, default=None)
    p.add_argument('--debug-output', action='store_true',
                   help='also write *.debug.csv including network_end')
    args = p.parse_args()

    try:
        mmdb_path = validated_path(args.mmdb_path, must_exist=True)
        out_dir = validated_path(args.out_dir)
    except (ValueError, FileNotFoundError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 1
    os.makedirs(out_dir, exist_ok=True)

    v4, v6 = extract_raw(mmdb_path)
    print(f'raw:    v4={len(v4)} v6={len(v6)}')
    assert_raw_sane(v4, 'ipv4-raw')
    assert_raw_sane(v6, 'ipv6-raw')

    m4 = merge_runs(v4)
    m6 = merge_runs(v6)
    assert_merged_sane(m4, 'ipv4', True, args.expect_v4_count)
    assert_merged_sane(m6, 'ipv6', False, args.expect_v6_count)

    v4_path = os.path.join(out_dir, 'blocks_ipv4_merged.csv')
    v6_path = os.path.join(out_dir, 'blocks_ipv6_merged.csv')
    write_csv(v4_path, m4, True,
              os.path.join(out_dir, 'blocks_ipv4_merged.debug.csv') if args.debug_output else None)
    write_csv(v6_path, m6, False,
              os.path.join(out_dir, 'blocks_ipv6_merged.debug.csv') if args.debug_output else None)

    print(f'merged: v4={len(m4)} (-{100 * (1 - len(m4) / len(v4)):.1f}%) '
          f'v6={len(m6)} (-{100 * (1 - len(m6) / len(v6)):.1f}%) total={len(m4) + len(m6)}')
    print(f'wrote {v4_path}')
    print(f'wrote {v6_path}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
