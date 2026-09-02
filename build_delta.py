#!/usr/bin/env python3
"""
Build the idempotent D1 delta SQL that converges live merged-GeoIP tables to a
target Country.mmdb release (Phase 5 engine of the convergence migration).

The live table contents are the baseline — there is no assumed/stored baseline
version to drift from. Live state arrives as CSV exports of the two tables
(network_start,country_iso_code per line, no header — the same shape
merge_mmdb.py emits and the CI keyset export converts to).

Gates (exit 2, nothing written):
    total delta rows  > --max-rows   (default 80000; lower to 60000 if the
                                      Phase 1 probe bills UPSERT as 2 writes)
    delta / live rows > --max-churn  (default 0.25)
A gate trip means "surprise": the convergence job must escalate to the
trickle full-rebuild path instead of applying an unbounded delta. Bootstrap
from an empty live set is intentionally gate-rejected here (use the trickle
loader for that).

Output delta.sql structure (applied via `wrangler d1 execute --remote --file`,
whole-file atomic per Phase 1 probe M7):
    DELETE batches by PK, then INSERT ... ON CONFLICT DO UPDATE batches
    (multi-row, each statement kept under a byte budget well below D1's
    100KB/statement limit), then meta rows LAST — a tag in meta therefore
    implies the data applied completely. Every statement is idempotent:
    re-applying the file converges to the same state.
"""

import argparse
import csv
import os
import sys

from merge_mmdb import extract_raw, merge_runs

MAX_STMT_BYTES = 80_000  # D1 hard limit is 100KB per statement; keep margin


def sql_str(s):
    return "'" + s.replace("'", "''") + "'"


def load_live(path, is_v4):
    live = {}
    with open(path, newline='', encoding='utf-8') as f:
        for row in csv.reader(f):
            if not row:
                continue
            key = int(row[0]) if is_v4 else row[0]
            live[key] = row[1]
    return live


def target_dicts(mmdb_path):
    v4, v6 = extract_raw(mmdb_path)
    t4 = {s: c for s, _e, c in merge_runs(v4)}
    t6 = {format(s, '032x'): c for s, _e, c in merge_runs(v6)}
    return t4, t6


def diff_family(live, target):
    upserts = {k: c for k, c in target.items() if live.get(k) != c}
    deletes = [k for k in live if k not in target]
    return upserts, deletes


def key_literal(k, is_v4):
    return str(k) if is_v4 else sql_str(k)


def emit_batches(f, head, tail, pieces):
    """Write multi-row statements, splitting on a byte budget. Returns max stmt bytes."""
    max_bytes = 0
    batch, size = [], len(head) + len(tail)

    def flush():
        nonlocal batch, size, max_bytes
        if batch:
            stmt = head + ",".join(batch) + tail
            max_bytes = max(max_bytes, len(stmt))
            f.write(stmt + "\n")
            batch, size = [], len(head) + len(tail)

    for piece in pieces:
        if batch and size + len(piece) + 1 > MAX_STMT_BYTES:
            flush()
        batch.append(piece)
        size += len(piece) + 1
    flush()
    return max_bytes


def emit_family(f, table, is_v4, upserts, deletes):
    # Keys sort deterministically within each family: v4 ints numerically,
    # v6 fixed-width lowercase hex lexicographically (== numerically).
    max_stmt = 0
    if deletes:
        max_stmt = max(max_stmt, emit_batches(
            f,
            f"DELETE FROM {table} WHERE network_start IN (",
            ");",
            (key_literal(k, is_v4) for k in sorted(deletes)),
        ))
    if upserts:
        max_stmt = max(max_stmt, emit_batches(
            f,
            f"INSERT INTO {table} (network_start,country_iso_code) VALUES ",
            " ON CONFLICT(network_start) DO UPDATE SET country_iso_code=excluded.country_iso_code;",
            (f"({key_literal(k, is_v4)},{sql_str(c)})" for k, c in sorted(upserts.items())),
        ))
    return max_stmt


def main():
    p = argparse.ArgumentParser(description='Build convergence delta.sql for D1')
    p.add_argument('--live-v4', required=True, help='CSV export of live merged_ipv4_data')
    p.add_argument('--live-v6', required=True, help='CSV export of live merged_ipv6_data')
    p.add_argument('--mmdb', required=True, help='target tag-pinned Country.mmdb')
    p.add_argument('--out', required=True, help='output delta.sql path')
    p.add_argument('--max-rows', type=int, default=80_000)
    p.add_argument('--max-churn', type=float, default=0.25)
    p.add_argument('--meta', action='append', default=[], metavar='KEY=VALUE',
                   help="meta rows written LAST (repeatable), e.g. --meta source_tag=202608270741")
    args = p.parse_args()

    for path in (args.live_v4, args.live_v6, args.mmdb):
        if not os.path.isfile(path):
            print(f'Error: {path} not found', file=sys.stderr)
            return 1

    live4 = load_live(args.live_v4, True)
    live6 = load_live(args.live_v6, False)
    target4, target6 = target_dicts(args.mmdb)

    up4, del4 = diff_family(live4, target4)
    up6, del6 = diff_family(live6, target6)
    total = len(up4) + len(del4) + len(up6) + len(del6)
    live_rows = len(live4) + len(live6)
    churn = total / live_rows if live_rows else float('inf')

    print(f'live:   v4={len(live4)} v6={len(live6)} total={live_rows}')
    print(f'target: v4={len(target4)} v6={len(target6)} total={len(target4) + len(target6)}')
    print(f'delta:  upserts v4={len(up4)} v6={len(up6)} | deletes v4={len(del4)} v6={len(del6)}'
          f' | total={total} churn={churn:.3%}')

    if total > args.max_rows or churn > args.max_churn:
        print(f'GATE REJECTED: delta {total} rows / churn {churn:.1%} exceeds '
              f'{args.max_rows} rows / {args.max_churn:.0%} — escalate to trickle rebuild',
              file=sys.stderr)
        return 2
    if total == 0:
        print('delta empty: live already equals target; no file written')
        return 0

    meta_pairs = []
    for item in args.meta:
        if '=' not in item:
            print(f'Error: --meta expects KEY=VALUE, got {item!r}', file=sys.stderr)
            return 1
        k, v = item.split('=', 1)
        meta_pairs.append((k, v))

    max_stmt = 0
    with open(args.out, 'w', encoding='utf-8') as f:
        f.write(f'-- convergence delta: {total} rows '
                f'(upserts {len(up4) + len(up6)}, deletes {len(del4) + len(del6)})\n')
        f.write('-- idempotent; meta rows are written LAST (tag present => apply complete)\n')
        max_stmt = max(max_stmt, emit_family(f, 'merged_ipv4_data', True, up4, del4))
        max_stmt = max(max_stmt, emit_family(f, 'merged_ipv6_data', False, up6, del6))
        if meta_pairs:
            values = ",".join(f"({sql_str(k)},{sql_str(v)})" for k, v in meta_pairs)
            f.write(f'INSERT INTO meta (key,value) VALUES {values} '
                    'ON CONFLICT(key) DO UPDATE SET value=excluded.value;\n')

    size = os.path.getsize(args.out)
    print(f'wrote {args.out}: {size:,} bytes, max statement {max_stmt:,} bytes '
          f'(limit 100,000), meta rows: {len(meta_pairs)}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
