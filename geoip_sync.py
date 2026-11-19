#!/usr/bin/env python3
"""
Daily GeoIP D1 sync job (Phase 3 bootstrap + Phase 5 convergence).

One long-lived database, one state machine keyed on its meta table:

  no meta.source_tag        -> BOOTSTRAP: build merged CSVs + quota-sized
                               chunk files from a pinned tag; apply at most
                               --chunks-per-run chunks per run (chunks are
                               self-marking and D1 --file imports are
                               whole-file atomic, probe M7 2026-09-02, so
                               marker present <=> chunk fully applied).
                               The bootstrap pin (meta.bootstrap_tag) is
                               written FIRST so a newer upstream release
                               mid-bootstrap cannot mix datasets. After the
                               last chunk: reconcile (counts + prefix-max
                               probes with the worker's exact query), then
                               write source_tag/mmdb_sha256/counts LAST.
  source_tag+sha == latest  -> VERIFY-ONLY: counts + probes, 0 writes.
  source_tag+sha != latest  -> CONVERGE: keyset-export the LIVE tables (the
                               baseline is the DB's own content; there is no
                               stored assumption that can drift), build the
                               gated delta (build_delta.py), snapshot a
                               time-travel bookmark, apply, verify, and on
                               mismatch restore the bookmark and fail loud.
  build_delta gate trip     -> exit 3 (ESCALATE): a human/trickle-rebuild
                               handles surprises; the daily job never
                               applies an unbounded delta.

All D1 access goes through a small adapter so the whole flow is testable
offline (probe measurements that shaped this design: M2-M6 all bill 1
rows_written/row on both PK layouts, M5 conflict-skips bill 0, M7 rollback):

  WranglerD1 - real remote D1 via `wrangler d1 execute --remote --json`
  SqliteD1   - offline dry-run (--dry-run) with identical semantics,
               including bookmark/restore (file snapshot)
"""

import argparse
import csv
import hashlib
import json
import os
import random
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone

from pathguard import validated_path
from sqlbatch import sql_str

HERE = os.path.dirname(os.path.realpath(__file__))
V4_TABLE = 'merged_ipv4_data'
V6_TABLE = 'merged_ipv6_data'
HEX32_RE = re.compile(r'^[0-9a-f]{32}$')
DB_NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')
TAG_RE = re.compile(r'^[0-9A-Za-z_.-]{1,64}$')
SHA256_RE = re.compile(r'^[0-9a-f]{64}$')
ALLOWED_TOOLS = ('merge_mmdb.py', 'build_chunks.py')
EXPORT_PAGE = 10_000  # rows per keyset page (conservative; D1 JSON result limits)
# wrangler/d1 execute can die mid-pagination on a transient API blip (observed
# 2026-10-23: non-zero rc, empty stderr). Retry a few times; SQL is idempotent.
WRANGLER_ATTEMPTS = 3
WRANGLER_RETRY_SLEEP = 2.0
WRANGLER_TIMEOUT_S = 600  # per wrangler invocation; a hung process must not eat the CI budget

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_ESCALATE = 3


class SyncError(Exception):
    pass


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def file_sha256(path):
    h = hashlib.sha256()
    with open(validated_path(path, must_exist=True), 'rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def strip_noise(text):
    """wrangler --json prints pure JSON on stdout; be tolerant anyway."""
    for i, ch in enumerate(text):
        if ch in '[{':
            return text[i:]
    raise SyncError(f'no JSON in output: {text[:200]!r}')


class SqliteD1:
    """Offline stand-in for a D1 database (dry-run and tests)."""

    def __init__(self, path):
        import sqlite3
        self.path = path
        self.con = sqlite3.connect(path)
        self.con.row_factory = sqlite3.Row

    def query(self, sql):
        return [dict(r) for r in self.con.execute(sql).fetchall()]

    def execute_sql(self, sql):
        # D1 --file imports are whole-file atomic (probe M7); mirror that here
        # so dry-run failure paths behave like production. executescript would
        # auto-commit statement by statement, so run complete statements inside
        # one explicit transaction instead. The toolchain emits one statement
        # per logical unit (multi-line DDL accumulates until its ';').
        import sqlite3
        self.con.execute('BEGIN')
        try:
            buf = ''
            for line in sql.splitlines(keepends=True):
                buf += line
                if sqlite3.complete_statement(buf):
                    self.con.execute(buf)
                    buf = ''
            if buf.strip():
                self.con.execute(buf)
            self.con.commit()
        except BaseException:
            self.con.rollback()
            raise

    def execute_file(self, path):
        with open(validated_path(path, must_exist=True), encoding='utf-8') as f:
            self.execute_sql(f.read())

    def table_exists(self, name):
        rows = self.query(f"SELECT name FROM sqlite_master WHERE type='table' AND name={sql_str(name)}")
        return bool(rows)

    def bookmark(self):
        snap = self.path + '.snapshot'
        self.con.commit()
        self.con.close()
        shutil.copyfile(self.path, snap)
        self.con = self._reopen()
        return snap

    def restore(self, bookmark):
        self.con.close()
        shutil.copyfile(bookmark, self.path)
        self.con = self._reopen()

    def _reopen(self):
        import sqlite3
        con = sqlite3.connect(self.path)
        con.row_factory = sqlite3.Row
        return con

    def close(self):
        self.con.commit()
        self.con.close()


class WranglerD1:
    """Real remote D1 via wrangler (JSON envelope per probe run 2026-09-02)."""

    def __init__(self, db):
        if not DB_NAME_RE.match(db or ''):
            raise SyncError(f'invalid D1 database name: {db!r}')
        self.db = db

    def _execute(self, *args):
        cmd = ['npx', '--no-install', 'wrangler', 'd1', 'execute', self.db,
               '-y', '--remote', '--json', *args]
        # self.db is regex-validated in __init__; SQL arguments are built
        # internally from literal-escaped values (sql_str / HEX32_RE / int).
        proc = None
        for attempt in range(1, WRANGLER_ATTEMPTS + 1):
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, cwd=HERE,
                                      timeout=WRANGLER_TIMEOUT_S)  # NOSONAR
            except subprocess.TimeoutExpired:
                proc = None
                detail = f'timeout after {WRANGLER_TIMEOUT_S}s'
            else:
                if proc.returncode == 0:
                    return proc
                detail = f'rc={proc.returncode}'
            if attempt < WRANGLER_ATTEMPTS:
                print(f'wrangler {detail}, retry {attempt}/{WRANGLER_ATTEMPTS}',
                      file=sys.stderr)
                time.sleep(WRANGLER_RETRY_SLEEP * attempt)
        if proc is None:
            raise SyncError(f'wrangler timed out after {WRANGLER_ATTEMPTS} attempts '
                            f'({WRANGLER_TIMEOUT_S}s each): d1 execute {self.db}')
        return proc

    @staticmethod
    def _fail(kind, detail, proc):
        # wrangler may report the real error on either stream; 2026-10-23
        # failure had empty stderr only. Keep both tails.
        err = (proc.stderr or '')[-400:]
        out = (proc.stdout or '')[-400:]
        raise SyncError(f'{kind}: {detail}\nrc={proc.returncode} stderr={err!r} stdout={out!r}')

    def query(self, sql):
        proc = self._execute('--command', sql)
        if proc.returncode != 0:
            self._fail('query failed', sql[:160], proc)
        data = json.loads(strip_noise(proc.stdout))
        return (data[0].get('results') or []) if data else []

    def execute_sql(self, sql):
        proc = self._execute('--command', sql)
        if proc.returncode != 0:
            self._fail('execute failed', sql[:160], proc)

    def execute_file(self, path):
        proc = self._execute('--file', path)
        if proc.returncode != 0:
            self._fail('file apply failed', path, proc)

    def table_exists(self, name):
        rows = self.query(f"SELECT name FROM sqlite_master WHERE type='table' AND name={sql_str(name)}")
        return bool(rows)

    def bookmark(self):
        # NOTE: exact time-travel JSON envelope unverified on this account
        # (open item); best-effort parse, and convergence correctness does
        # not depend on it (delta statements are idempotent) — only the
        # automatic rollback convenience does.
        proc = subprocess.run(['npx', '--no-install', 'wrangler', 'd1',
                               'time-travel', 'info', self.db, '--json'],
                              capture_output=True, text=True, cwd=HERE,
                              timeout=WRANGLER_TIMEOUT_S)
        m = re.search(r'"bookmark"\s*:\s*"([^"]+)"', proc.stdout + proc.stderr)
        if proc.returncode != 0 or not m:
            self._fail('time-travel info failed', self.db, proc)
        return m.group(1)

    def restore(self, bookmark):
        proc = subprocess.run(['npx', '--no-install', 'wrangler', 'd1',
                               'time-travel', 'restore', self.db,
                               '--bookmark', bookmark, '-y'],
                              capture_output=True, text=True, cwd=HERE,
                              timeout=WRANGLER_TIMEOUT_S)
        if proc.returncode != 0:
            self._fail('time-travel restore failed', self.db, proc)

    def close(self):
        pass


# ------------------------------------------------------------ helpers

def meta_get(db, key):
    rows = db.query(f'SELECT value FROM meta WHERE key = {sql_str(key)}')
    return rows[0]['value'] if rows else None


def meta_set_sql(pairs):
    values = ','.join(f'({sql_str(k)},{sql_str(v)})' for k, v in pairs)
    return (f'INSERT INTO meta (key,value) VALUES {values} '
            'ON CONFLICT(key) DO UPDATE SET value=excluded.value;')


def table_count(db, table):
    rows = db.query(f'SELECT COUNT(*) AS c FROM {table}')
    return int(rows[0]['c'])


def count_csv(path):
    with open(validated_path(path, must_exist=True), newline='', encoding='utf-8') as f:
        return sum(1 for r in csv.reader(f) if r)


def run_tool(script, *args):
    if script not in ALLOWED_TOOLS:
        raise SyncError(f'refusing to run tool outside allowlist: {script!r}')
    # script is allowlisted; args are paths/tags/shas already validated at
    # the resolve_source / main boundary before reaching here.
    proc = subprocess.run([sys.executable, os.path.join(HERE, script), *args], cwd=HERE)  # NOSONAR
    if proc.returncode != 0:
        raise SyncError(f'{script} failed (rc={proc.returncode})')


def build_merged(mmdb, work):
    out = os.path.join(work, 'merged')
    run_tool('merge_mmdb.py', mmdb, out)
    return (os.path.join(out, 'blocks_ipv4_merged.csv'),
            os.path.join(out, 'blocks_ipv6_merged.csv'))


def _load_probe_keys(csv_path, is_v4):
    keys = []
    with open(validated_path(csv_path, must_exist=True), newline='', encoding='utf-8') as f:
        for r in csv.reader(f):
            if r:
                keys.append((int(r[0]) if is_v4 else r[0], r[1]))
    return keys


def _probe_family(db, table, keys, is_v4, rng, n):
    bad = 0
    for k, expect in rng.sample(keys, min(n, len(keys))):  # NOSONAR - verification probes only
        lit = str(k) if is_v4 else sql_str(k)
        rows = db.query(f'SELECT country_iso_code FROM {table} '
                        f'WHERE network_start <= {lit} '
                        f'ORDER BY network_start DESC LIMIT 1')
        got = rows[0]['country_iso_code'] if rows else None
        if got != expect:
            bad += 1
            if bad <= 3:
                print(f'  probe mismatch: {table} key={k} db={got} target={expect}',
                      file=sys.stderr)
    return bad


def probe_check(db, v4csv, v6csv, n_probes=200, seed=11):
    """Sample exact target keys and run the worker's lookup query against D1."""
    rng = random.Random(seed)  # NOSONAR - seeded probes for deterministic verification, not a security context
    bad = 0
    for csv_path, table, is_v4 in ((v4csv, V4_TABLE, True), (v6csv, V6_TABLE, False)):
        keys = _load_probe_keys(csv_path, is_v4)
        bad += _probe_family(db, table, keys, is_v4, rng, n_probes // 2)
    return bad


def _export_page(db, table, cursor, is_v4):
    lit = str(cursor) if is_v4 else sql_str(cursor)
    return db.query(f'SELECT network_start, country_iso_code FROM {table} '
                    f'WHERE network_start > {lit} '
                    f'ORDER BY network_start LIMIT {EXPORT_PAGE}')


def _next_cursor(last, is_v4):
    if is_v4:
        return int(last)
    if not HEX32_RE.match(str(last)):
        raise SyncError(f'invalid IPv6 key during export: {last!r}')
    return str(last)


def export_table(db, table, out_csv, is_v4):
    """Keyset-paginated full export (reads only). Returns row count."""
    n = 0
    # v4 starts at -1 so the network_start=0 row (0.0.0.0/8) is included;
    # v6 starts at '' — every 32-hex key sorts after the empty string.
    cursor = -1 if is_v4 else ''
    with open(validated_path(out_csv), 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        while True:
            rows = _export_page(db, table, cursor, is_v4)
            if not rows:
                break
            for r in rows:
                w.writerow([r['network_start'], r['country_iso_code']])
            cursor = _next_cursor(rows[-1]['network_start'], is_v4)
            n += len(rows)
            if len(rows) < EXPORT_PAGE:
                break
    return n


def resolve_source(args, work):
    """Return (tag, sha256, mmdb_path): overrides win, else fetch_mmdb.sh."""
    work = validated_path(work)
    if args.mmdb:
        if not args.tag or not TAG_RE.match(args.tag):
            raise SyncError('--mmdb override requires a valid --tag')
        mmdb = validated_path(args.mmdb, must_exist=True)
        sha = args.sha256 or file_sha256(mmdb)
        if not SHA256_RE.match(sha):
            raise SyncError(f'invalid sha256: {sha!r}')
        return args.tag, sha, mmdb
    if args.tag and not TAG_RE.match(args.tag):
        raise SyncError(f'invalid release tag: {args.tag!r}')
    cmd = [os.path.join(HERE, 'fetch_mmdb.sh'), work]
    if args.tag:
        cmd.append(args.tag)
    # cmd = fixed repo script + validated work dir + regex-validated tag.
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=HERE)  # NOSONAR
    if proc.returncode != 0:
        raise SyncError(f'fetch_mmdb.sh failed: {proc.stderr[-400:]}')
    parts = proc.stdout.strip().split()
    if len(parts) != 3 or not TAG_RE.match(parts[0]) or not SHA256_RE.match(parts[1]):
        raise SyncError(f'unexpected fetch_mmdb output: {proc.stdout[:200]!r}')
    return parts[0], parts[1], validated_path(parts[2], must_exist=True)


# ------------------------------------------------------------ state machine

def ensure_schema(db):
    if not db.table_exists('meta'):
        print('fresh database: applying migrations/0002')
        db.execute_file(os.path.join(HERE, 'migrations', '0002_merged_pk_schema.sql'))


def run_bootstrap(db, args, work, tag, sha, mmdb):
    ensure_schema(db)
    pinned = meta_get(db, 'bootstrap_tag')
    if pinned and pinned != tag:
        if args.dry_run and args.mmdb:
            raise SyncError(f'bootstrap pinned to {pinned} but --mmdb override targets {tag}; '
                            'use a matching --tag/--mmdb or a fresh --sqlite-path '
                            '(offline mode will not download the pinned release)')
        print(f'bootstrap pinned to {pinned}; ignoring newer release {tag} until complete')
        tag, sha, mmdb = resolve_source(args.__class__(**{**vars(args), 'mmdb': None, 'tag': pinned}), work)
    if not pinned:
        db.execute_sql(meta_set_sql([('bootstrap_tag', tag), ('bootstrap_started', utcnow())]))

    v4csv, v6csv = build_merged(mmdb, work)
    chunks_dir = os.path.join(work, 'chunks')
    run_tool('build_chunks.py', '--v4-csv', v4csv, '--v6-csv', v6csv,
             '--tag', tag, '--sha256', sha, '--out-dir', chunks_dir)
    with open(validated_path(os.path.join(chunks_dir, 'manifest.json'), must_exist=True),
              encoding='utf-8') as f:
        manifest = json.load(f)

    applied_now = 0
    for ch in manifest['chunks']:
        marker = ch['file'].removesuffix('.sql')
        existing = meta_get(db, marker)
        if existing is not None:
            expected_marker = f'{ch["sha"]}:{ch["rows"]}'
            if existing != expected_marker:
                raise SyncError(f'chunk marker mismatch for {marker}: db={existing!r} '
                                f'manifest={expected_marker!r} — dataset changed mid-bootstrap? '
                                'manual inspection required')
            continue
        if applied_now >= args.chunks_per_run:
            print(f'quota guard: {args.chunks_per_run} chunk(s) per run; resume next run')
            return 'partial', applied_now
        print(f'applying {ch["file"]} ({ch["rows"]} rows)')
        db.execute_file(os.path.join(chunks_dir, ch['file']))
        applied_now += 1

    c4, c6 = table_count(db, V4_TABLE), table_count(db, V6_TABLE)
    e4, e6 = count_csv(v4csv), count_csv(v6csv)
    if (c4, c6) != (e4, e6):
        raise SyncError(f'bootstrap reconcile: count mismatch db=({c4},{c6}) expected=({e4},{e6})')
    bad = probe_check(db, v4csv, v6csv)
    if bad:
        raise SyncError(f'bootstrap reconcile: {bad} probe mismatches')
    db.execute_sql(meta_set_sql([
        ('source_tag', tag), ('mmdb_sha256', sha),
        ('v4_count', str(c4)), ('v6_count', str(c6)),
        ('bootstrapped_at', utcnow()),
    ]))
    print(f'bootstrap COMPLETE: tag={tag} v4={c4} v6={c6} (probes ok)')
    return 'complete', applied_now


def run_converge(db, args, work, tag, sha, mmdb):
    cur_tag, cur_sha = meta_get(db, 'source_tag'), meta_get(db, 'mmdb_sha256')
    v4csv, v6csv = build_merged(mmdb, work)
    e4, e6 = count_csv(v4csv), count_csv(v6csv)

    if cur_tag == tag and cur_sha == sha:
        c4, c6 = table_count(db, V4_TABLE), table_count(db, V6_TABLE)
        bad = probe_check(db, v4csv, v6csv, n_probes=64)
        if (c4, c6) == (e4, e6) and not bad:
            print(f'up to date with {tag} (v4={c4} v6={c6}, probes ok) — 0 writes')
            return 'uptodate'
        # Drift with a matching tag (e.g. a failed restore after a bad apply)
        # must self-heal, not fail identically every day: fall through to the
        # normal convergence path (export -> gated delta -> verify).
        print(f'verify-only DRIFT: counts db=({c4},{c6}) expected=({e4},{e6}) '
              f'probes_bad={bad} — falling through to convergence', file=sys.stderr)

    print(f'converging {cur_tag} -> {tag}')
    live4, live6 = os.path.join(work, 'live_v4.csv'), os.path.join(work, 'live_v6.csv')
    n4 = export_table(db, V4_TABLE, live4, True)
    n6 = export_table(db, V6_TABLE, live6, False)
    print(f'exported live tables: v4={n4} v6={n6} (reads only, 0 writes)')

    delta = os.path.join(work, 'delta.sql')
    rc = subprocess.run(
        [sys.executable, os.path.join(HERE, 'build_delta.py'),
         '--live-v4', live4, '--live-v6', live6, '--mmdb', mmdb, '--out', delta,
         '--max-rows', str(args.max_delta_rows), '--max-churn', str(args.max_churn),
         '--meta', f'source_tag={tag}', '--meta', f'mmdb_sha256={sha}',
         '--meta', f'v4_count={e4}', '--meta', f'v6_count={e6}',
         '--meta', f'converged_at={utcnow()}'],
        cwd=HERE).returncode
    if rc == 2:  # build_delta gate rejection (its documented exit code)
        print('ESCALATE: delta gate rejected the change set — manual trickle '
              'rebuild required (see migration plan); refusing to apply', file=sys.stderr)
        return 'escalate'
    if rc != 0:
        raise SyncError(f'build_delta failed (rc={rc})')

    bookmark = db.bookmark()
    db.execute_file(delta)

    c4, c6 = table_count(db, V4_TABLE), table_count(db, V6_TABLE)
    bad = probe_check(db, v4csv, v6csv)
    newtag = meta_get(db, 'source_tag')
    if (c4, c6) != (e4, e6) or bad or newtag != tag:
        print(f'POST-APPLY VERIFY FAILED: counts db=({c4},{c6}) expected=({e4},{e6}) '
              f'probes_bad={bad} tag={newtag!r} — restoring bookmark', file=sys.stderr)
        db.restore(bookmark)
        raise SyncError('delta rolled back to pre-apply state; next run re-converges')
    print(f'CONVERGED to {tag}: v4={c4} v6={c6} (probes ok)')
    return 'converged'


def main():
    p = argparse.ArgumentParser(description='Daily GeoIP D1 sync (bootstrap/converge)')
    p.add_argument('--db', help='long-lived D1 database name (required unless --dry-run)')
    p.add_argument('--dry-run', action='store_true',
                   help='offline mode: SqliteD1 at --sqlite-path, no network unless --mmdb given')
    p.add_argument('--sqlite-path', default='tmp/geoip_sync/live.sqlite')
    p.add_argument('--work', default='tmp/geoip_sync')
    p.add_argument('--tag', help='pin a release tag (default: resolve latest)')
    p.add_argument('--mmdb', help='use a local mmdb instead of downloading (offline tests)')
    p.add_argument('--sha256', help='sha of --mmdb (default: computed)')
    p.add_argument('--chunks-per-run', type=int, default=1,
                   help='bootstrap chunks per run (free quota: keep at 1; paid: raise)')
    p.add_argument('--max-delta-rows', type=int, default=80_000)
    p.add_argument('--max-churn', type=float, default=0.25)
    args = p.parse_args()

    if not args.dry_run and not args.db:
        print('Error: --db is required unless --dry-run', file=sys.stderr)
        return EXIT_ERROR

    if args.chunks_per_run < 1:
        print('Error: --chunks-per-run must be >= 1', file=sys.stderr)
        return EXIT_ERROR
    if not args.dry_run and args.chunks_per_run > 1:
        # Free plan: one ~72.6k-row chunk/day fits the 100k rows_written quota;
        # two chunks (~145k) hard-fail it. Only Workers Paid may raise this.
        print('Error: free plan allows --chunks-per-run 1 only '
              '(2 chunks ~145k rows > 100k daily quota); raise only under Workers Paid',
              file=sys.stderr)
        return EXIT_ERROR

    work = validated_path(args.work)
    os.makedirs(work, exist_ok=True)

    if args.dry_run:
        sqlite_path = validated_path(args.sqlite_path)
        os.makedirs(os.path.dirname(sqlite_path) or '.', exist_ok=True)
        db = SqliteD1(sqlite_path)
    else:
        db = WranglerD1(args.db)

    try:
        tag, sha, mmdb = resolve_source(args, work)
        print(f'source: tag={tag} sha256={sha[:16]}... mmdb={mmdb}')
        ensure_schema(db) if not args.dry_run else None
        has_tag = db.table_exists('meta') and meta_get(db, 'source_tag')
        if not has_tag:
            state, applied = run_bootstrap(db, args, work, tag, sha, mmdb)
            print(f'result: bootstrap {state} (chunks applied this run: {applied})')
        else:
            state = run_converge(db, args, work, tag, sha, mmdb)
            print(f'result: {state}')
        return EXIT_ESCALATE if state == 'escalate' else EXIT_OK
    except SyncError as exc:
        print(f'SYNC FAILED: {exc}', file=sys.stderr)
        return EXIT_ERROR
    finally:
        db.close()


if __name__ == '__main__':
    sys.exit(main())
