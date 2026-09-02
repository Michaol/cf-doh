#!/usr/bin/env bash
# ============================================================
# Phase 1: D1 platform probe — measures the facts the migration
# plan depends on, against a scratch DB deleted afterwards.
#
# Usage: ./d1_probe.sh <scratch-db-name>
# Requires: CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_API_TOKEN in env;
#           node_modules installed (npm ci); jq; python3.
#
# Measurements (each prints actual rows_read / rows_written):
#   M1  migrations/0002 acceptance on remote D1
#       (WITHOUT ROWID + CHECK, no secondary indexes) and DDL cost
#   M2  INSERT 1000 rows, INTEGER-PK table          (expect 1000 written)
#   M3  INSERT 1000 rows, WITHOUT-ROWID TEXT-PK     (expect 1000 written)
#   M4  UPSERT (ON CONFLICT DO UPDATE) of same 1000 (expect 1000; if 2000,
#       weekly delta estimate doubles and the escalation gate drops to 60k)
#   M5  INSERT OR IGNORE of 1000 existing rows      (expect 0; if nonzero,
#       trickle-rebuild chunk sizing must be recomputed)
#   M6  DELETE 1000 rows by PK                      (expect 1000 written)
#   M7  --file mid-file failure: do earlier statements roll back?
# Total cost: < 10k rows_written. All output goes to the CI log.
# ============================================================
set -euo pipefail

DB="${1:?usage: d1_probe.sh <scratch-db-name>}"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

wr() { npx wrangler d1 execute "$DB" -y --remote "$@"; }

# Best-effort rows_written/rows_read extraction; handles both wrangler JSON
# shapes (per-statement array from --command, import summary from --file).
parse_meta() {
    jq -r '
      [.. | objects | select(has("rows_written")) | .rows_written] as $w |
      [.. | objects | select(has("rows_read")) | .rows_read] as $r |
      "rows_written=\(($w | add) // "n/a") rows_read=\(($r | add) // "n/a")"
    ' 2>/dev/null || echo "(unparseable wrangler output — see raw JSON above)"
}

run_cmd() { # run_cmd <label> <sql>
    echo "--- $1"
    if ! wr --command "$2" --json > "$WORK/out.json" 2> "$WORK/err.log"; then
        echo "COMMAND FAILED:"
        cat "$WORK/err.log" "$WORK/out.json" || true
        return 1
    fi
    parse_meta < "$WORK/out.json"
}

echo "=== M1: apply migrations/0002 (WITHOUT ROWID / CHECK acceptance + DDL cost) ==="
if ! wr --file=migrations/0002_merged_pk_schema.sql --json > "$WORK/out.json" 2>&1; then
    echo "DDL REJECTED by remote D1 — raw output:"
    cat "$WORK/out.json"
    echo "FALLBACK (pre-authorized): drop STRICT/CHECK, IPv6 as rowid+UNIQUE (2 writes/row)"
    exit 1
fi
parse_meta < "$WORK/out.json"

echo
echo "=== generate 1000-row SQL payloads ==="
python3 - "$WORK" <<'PYEOF'
import sys
work = sys.argv[1]
rows_v4 = ",".join(f"({1000000+i},'T{i%97}')" for i in range(1000))
rows_v6 = ",".join(f"('{format(i,'032x')}','T{i%97}')" for i in range(1, 1001))
open(f'{work}/p_v4_insert.sql', 'w').write(
    f"INSERT INTO merged_ipv4_data (network_start,country_iso_code) VALUES {rows_v4};")
open(f'{work}/p_v6_insert.sql', 'w').write(
    f"INSERT INTO merged_ipv6_data (network_start,country_iso_code) VALUES {rows_v6};")
open(f'{work}/p_v4_upsert.sql', 'w').write(
    f"INSERT INTO merged_ipv4_data (network_start,country_iso_code) VALUES {rows_v4} "
    "ON CONFLICT(network_start) DO UPDATE SET country_iso_code=excluded.country_iso_code;")
open(f'{work}/p_v4_ignore.sql', 'w').write(
    f"INSERT OR IGNORE INTO merged_ipv4_data (network_start,country_iso_code) VALUES {rows_v4};")
keys = ",".join(str(1000000+i) for i in range(1000))
open(f'{work}/p_v4_delete.sql', 'w').write(
    f"DELETE FROM merged_ipv4_data WHERE network_start IN ({keys});")
rb = ("INSERT INTO meta (key,value) VALUES "
      + ",".join(f"('rb{i}','x')" for i in range(50))
      + ";\nTHIS IS A DELIBERATE SYNTAX ERROR;\n")
open(f'{work}/p_rollback.sql', 'w').write(rb)
print("payloads written")
PYEOF

echo
echo "=== M2: INSERT 1000 rows, INTEGER-PK (expect rows_written=1000) ==="
run_cmd M2 "$(cat "$WORK/p_v4_insert.sql")"

echo
echo "=== M3: INSERT 1000 rows, WITHOUT ROWID TEXT-PK (expect rows_written=1000) ==="
run_cmd M3 "$(cat "$WORK/p_v6_insert.sql")"

echo
echo "=== M4: UPSERT same 1000 v4 rows (expect 1000; 2000 => lower gate to 60k) ==="
run_cmd M4 "$(cat "$WORK/p_v4_upsert.sql")"

echo
echo "=== M5: INSERT OR IGNORE same 1000 v4 rows (expect 0) ==="
run_cmd M5 "$(cat "$WORK/p_v4_ignore.sql")"

echo
echo "=== M6: DELETE 1000 v4 rows by PK (expect 1000) ==="
run_cmd M6 "$(cat "$WORK/p_v4_delete.sql")"

echo
echo "=== M7: mid-file failure rollback ==="
if wr --file="$WORK/p_rollback.sql" --json > "$WORK/out.json" 2> "$WORK/err.log"; then
    echo "UNEXPECTED: file containing a syntax error reported success"
    cat "$WORK/out.json"
else
    echo "file failed as expected (stderr tail):"
    tail -3 "$WORK/err.log" || true
fi
run_cmd "M7 survivor check" "SELECT COUNT(*) AS survivors FROM meta WHERE key LIKE 'rb%';"
echo "(survivors=0 => whole-file rollback confirmed; survivors=50 => partial apply is visible)"

echo
echo "=== probe complete (scratch DB '$DB' is deleted by the workflow's always-step) ==="
