#!/usr/bin/env python3
"""
Prove merged CSVs are query-equivalent to the raw mmdb for the worker lookup:

    greatest network_start <= ip  ->  country_iso_code

Compares lookups on the raw extraction (straight from the mmdb, the same
semantics as the pre-merge D1 tables) against lookups on the merged CSVs
(merge_mmdb.py output) over:
  - every sampled raw network's start AND end (boundary probes)
  - uniformly random addresses across the full space

Any mismatch exits non-zero. Run this against the exact production DDL output
before any cutover (migration plan Phase 2 gate).
"""

import argparse
import bisect
import csv
import random
import sys

from merge_mmdb import extract_raw


def load_merged(path, is_v4):
    keys, vals = [], []
    with open(path, newline='', encoding='utf-8') as f:
        for row in csv.reader(f):
            keys.append(int(row[0]) if is_v4 else int(row[0], 16))
            vals.append(row[1])
    if keys != sorted(keys):
        raise AssertionError(f'{path}: merged CSV is not sorted by network_start')
    return keys, vals


def lookup(keys, vals, ip):
    i = bisect.bisect_right(keys, ip)
    return vals[i - 1] if i else None


def verify_family(label, raw, csv_path, is_v4, bits, n_probes, n_boundary):
    """Probe one address family; return True on zero mismatches."""
    keys, vals = load_merged(csv_path, is_v4)
    rkeys = [r[0] for r in raw]
    rvals = [r[2] for r in raw]
    sample = random.sample(raw, min(n_boundary, len(raw)))  # NOSONAR - seeded probes for an equivalence test, not a security context
    probes = ([s for s, _, _ in sample]
              + [e for _, e, _ in sample]
              + [random.getrandbits(bits) for _ in range(n_probes)])  # NOSONAR - test probe addresses only
    mismatches = 0
    first = None
    for ip in probes:
        a = lookup(rkeys, rvals, ip)
        b = lookup(keys, vals, ip)
        if a != b:
            mismatches += 1
            if first is None:
                first = (ip, a, b)
    status = 'OK' if mismatches == 0 else 'MISMATCH'
    extra = f' first={first}' if first else ''
    print(f'{label}: raw={len(raw)} merged={len(keys)} probes={len(probes)} '
          f'mismatches={mismatches} [{status}]{extra}')
    return mismatches == 0


def main():
    p = argparse.ArgumentParser(description='Verify merged GeoIP CSV equivalence')
    p.add_argument('mmdb_path')
    p.add_argument('v4_csv')
    p.add_argument('v6_csv')
    p.add_argument('--probes', type=int, default=120000,
                   help='random probes per family (default 120000)')
    p.add_argument('--boundary-samples', type=int, default=40000,
                   help='raw networks whose start+end are probed (default 40000)')
    p.add_argument('--seed', type=int, default=7)
    args = p.parse_args()

    random.seed(args.seed)
    raw4, raw6 = extract_raw(args.mmdb_path)
    ok4 = verify_family('IPv4', raw4, args.v4_csv, True, 32,
                        args.probes, args.boundary_samples)
    ok6 = verify_family('IPv6', raw6, args.v6_csv, False, 128,
                        args.probes, args.boundary_samples)
    return 0 if ok4 and ok6 else 1


if __name__ == '__main__':
    sys.exit(main())
