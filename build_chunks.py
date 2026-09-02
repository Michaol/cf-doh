#!/usr/bin/env python3
"""
Split merged GeoIP CSVs into quota-sized bootstrap chunk files (Phase 3).

The one-time bootstrap of the long-lived D1 cannot land in a single day
(~508k rows > the 100k rows_written free daily quota): it trickles in over
--days daily chunks (default 7 -> ~72.6k rows/day, within the 78k planning
budget). Each chunk file is SELF-MARKING: it ends with a meta upsert
('chunk_NNN' -> '<chunk-sha>:<rows>'), and D1 applies `--file` imports
whole-file-atomically (probe M7, measured 2026-09-02), so
"marker present <=> chunk fully applied". The bootstrap loader therefore
needs no separate progress state and resumes after any failure by re-running.

Data rows are emitted as multi-row INSERT ... ON CONFLICT(network_start)
DO UPDATE statements (probe M4: upserts bill 1 rows_written/row on both PK
layouts), kept under an 80KB budget (D1 hard limit: 100KB/statement).

Outputs (in --out-dir):
    chunk_000.sql .. chunk_NNN.sql
    manifest.json {tag, mmdb_sha256, total_rows, chunk_rows,
                   chunks: [{file, rows, sha}]}

The final source_tag/mmdb_sha256 meta rows are NOT written here: per the
migration plan they are committed only after the post-bootstrap
reconciliation passes (tag present => whole dataset verified).
"""

import argparse
import csv
import hashlib
import json
import math
import os
import sys

from pathguard import validated_path
from sqlbatch import iter_batches, sql_str

CHUNK_ROW_CAP = 78_000  # planning budget per day (< 100k quota, leaves slack)
UPSERT_TAIL = (" ON CONFLICT(network_start) DO UPDATE "
               "SET country_iso_code=excluded.country_iso_code;")


def upsert_head(table):
    return f"INSERT INTO {table} (network_start,country_iso_code) VALUES "


def read_rows(path, is_v4):
    """CSV (network_start,country) -> list of (table, values-literal) pieces."""
    table = 'merged_ipv4_data' if is_v4 else 'merged_ipv6_data'
    rows = []
    with open(validated_path(path, must_exist=True), newline='', encoding='utf-8') as f:
        for r in csv.reader(f):
            if not r:
                continue
            key = r[0] if is_v4 else sql_str(r[0])
            rows.append((table, f"({key},{sql_str(r[1])})"))
    return rows


def chunk_marker(idx, row_count, sha):
    return (f"INSERT INTO meta (key,value) VALUES "
            f"({sql_str(f'chunk_{idx:03d}')},{sql_str(f'{sha}:{row_count}')}) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value;")


def write_chunk(path, idx, rows):
    sha = hashlib.sha256("|".join(piece for _t, piece in rows).encode('utf-8')).hexdigest()
    max_stmt = 0
    with open(validated_path(path), 'w', encoding='utf-8') as f:
        f.write(f"-- bootstrap chunk {idx:03d}: {len(rows)} rows, sha {sha}\n")
        groups = []  # consecutive rows per table (chunks may straddle v4/v6)
        for table, piece in rows:
            if groups and groups[-1][0] == table:
                groups[-1][1].append(piece)
            else:
                groups.append((table, [piece]))
        for table, pieces in groups:
            for stmt in iter_batches(upsert_head(table), UPSERT_TAIL, pieces):
                max_stmt = max(max_stmt, len(stmt))
                f.write(stmt + "\n")
        f.write(chunk_marker(idx, len(rows), sha) + "\n")
    return sha, max_stmt


def main():
    p = argparse.ArgumentParser(description='Build bootstrap chunk files for D1 trickle load')
    p.add_argument('--v4-csv', required=True, help='merged IPv4 CSV (merge_mmdb.py output)')
    p.add_argument('--v6-csv', required=True, help='merged IPv6 CSV (merge_mmdb.py output)')
    p.add_argument('--tag', required=True, help='Loyalsoldier release tag of the source mmdb')
    p.add_argument('--sha256', required=True, help='sha256 of the source mmdb')
    p.add_argument('--out-dir', required=True)
    p.add_argument('--days', type=int, default=7)
    args = p.parse_args()

    v4 = read_rows(args.v4_csv, True)
    v6 = read_rows(args.v6_csv, False)
    all_rows = v4 + v6
    total = len(all_rows)
    if total == 0:
        print('Error: no rows to chunk', file=sys.stderr)
        return 1
    per_chunk = math.ceil(total / args.days)
    if per_chunk > CHUNK_ROW_CAP:
        need = math.ceil(total / CHUNK_ROW_CAP)
        print(f'Error: {args.days} days -> {per_chunk} rows/chunk exceeds the {CHUNK_ROW_CAP} '
              f'cap; use --days {need} or more (or Workers Paid and load in one run)',
              file=sys.stderr)
        return 1

    out_dir = validated_path(args.out_dir)
    os.makedirs(out_dir, exist_ok=True)

    chunks = []
    max_stmt_seen = 0
    for i in range(args.days):
        part = all_rows[i * per_chunk:(i + 1) * per_chunk]
        if not part:
            break
        fname = f'chunk_{i:03d}.sql'
        sha, max_stmt = write_chunk(os.path.join(out_dir, fname), i, part)
        max_stmt_seen = max(max_stmt_seen, max_stmt)
        chunks.append({'file': fname, 'rows': len(part), 'sha': sha})

    manifest = {'tag': args.tag, 'mmdb_sha256': args.sha256, 'total_rows': total,
                'chunk_rows': per_chunk, 'chunks': chunks}
    with open(validated_path(os.path.join(out_dir, 'manifest.json')), 'w', encoding='utf-8') as f:
        json.dump(manifest, f, indent=1)

    print(f'chunks: {len(chunks)} x <= {per_chunk} rows (cap {CHUNK_ROW_CAP}); '
          f'total {total}; max statement {max_stmt_seen:,} bytes; manifest written to {out_dir}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
