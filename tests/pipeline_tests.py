#!/usr/bin/env python3
"""Offline regression for the GeoIP sync pipeline (no Cloudflare credentials).

Covers: bootstrap -> verify-only -> converge -> gate escalation, drift
self-heal, whole-file atomicity of the sqlite stand-in, pathguard confinement,
chunk-marker tamper rejection, quota/pin guards, and (when an mmdb is present)
the 400k-probe merge equivalence check.

Requires >=1 mmdb in tmp/mm/ (two for the converge/gate tests). CI fetches the
two latest releases via fetch_mmdb.sh; locally any Loyalsoldier Country.mmdb
named tmp/mm/*.mmdb works. Without mmdb files the data tests SKIP (guards and
unit tests still run).
"""
import glob
import os
import re
import shutil
import sqlite3
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
WORK = os.path.join(ROOT, 'tmp', 'test_pipeline')
results = []


def check(label, cond, detail=''):
    results.append((label, bool(cond)))
    print(f"{'PASS' if cond else 'FAIL'}  {label}  {detail}")


def sync(sqlite_path, *extra, work=None):
    cmd = [PY, os.path.join(ROOT, 'geoip_sync.py'), '--dry-run',
           '--sqlite-path', sqlite_path, '--work', work or WORK, *extra]
    p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def reset(path):
    for suffix in ('', '.snapshot'):
        try:
            os.remove(path + suffix)
        except FileNotFoundError:
            pass


def main():
    os.makedirs(WORK, exist_ok=True)
    mmdb_files = sorted(glob.glob(os.path.join(ROOT, 'tmp', 'mm', '*.mmdb')))
    # tag = filename stem (Loyalsoldier tags are chronological YYYYMMDDHHMM)
    tagged = [(re.sub(r'^Country-', '', os.path.splitext(os.path.basename(p))[0]), p)
              for p in mmdb_files]
    tagged.sort(key=lambda t: t[0])

    db = os.path.join(WORK, 'live.sqlite')

    if tagged:
        tag_a, mmdb_a = tagged[0]
        reset(db)
        rc, out = sync(db, '--mmdb', mmdb_a, '--tag', tag_a, '--chunks-per-run', '7')
        check('bootstrap complete (counts + probes)', rc == 0 and 'bootstrap COMPLETE' in out,
              f'rc={rc}')

        rc, out = sync(db, '--mmdb', mmdb_a, '--tag', tag_a)
        check('verify-only rerun: 0 writes', rc == 0 and 'uptodate' in out and '0 writes' in out,
              f'rc={rc}')

        if len(tagged) >= 2:
            tag_b, mmdb_b = tagged[-1]
            rc, out = sync(db, '--mmdb', mmdb_b, '--tag', tag_b)
            check('converge to newer release', rc == 0 and 'CONVERGED' in out, f'rc={rc}')

            rc, out = sync(db, '--mmdb', mmdb_a, '--tag', tag_a, '--max-delta-rows', '1')
            check('gate trip -> exit 3 escalate, nothing applied', rc == 3 and 'escalate' in out,
                  f'rc={rc}')

            # drift self-heal: corrupt the live table under a matching tag
            con = sqlite3.connect(db)
            con.execute('DELETE FROM merged_ipv4_data WHERE network_start IN '
                        '(SELECT network_start FROM merged_ipv4_data LIMIT 100)')
            con.commit()
            con.close()
            rc, out = sync(db, '--mmdb', mmdb_b, '--tag', tag_b)
            check('verify-only drift falls through and self-heals',
                  rc == 0 and 'DRIFT' in out and 'CONVERGED' in out, f'rc={rc}')
        else:
            print('SKIP  converge/gate/drift tests (need >=2 mmdb files)')

        # merge equivalence: 400k probes against the newest merged CSVs
        tag_n, mmdb_n = tagged[-1]
        merged_dir = os.path.join(WORK, 'merged_verify')
        p = subprocess.run([PY, os.path.join(ROOT, 'merge_mmdb.py'), mmdb_n, merged_dir],
                           cwd=ROOT, capture_output=True, text=True)
        if p.returncode == 0:
            p = subprocess.run([PY, os.path.join(ROOT, 'verify_merge.py'), mmdb_n,
                                os.path.join(merged_dir, 'blocks_ipv4_merged.csv'),
                                os.path.join(merged_dir, 'blocks_ipv6_merged.csv')],
                               cwd=ROOT, capture_output=True, text=True)
            check('merge equivalence: 400k probes zero mismatch',
                  p.returncode == 0 and 'mismatches=0' in p.stdout,
                  p.stdout.strip().replace('\n', ' | ')[:160])
        else:
            check('merge equivalence: 400k probes zero mismatch', False, 'merge_mmdb failed')

        # chunk-marker tamper rejection (fresh partial bootstrap)
        db2 = os.path.join(WORK, 'tamper.sqlite')
        reset(db2)
        rc, out = sync(db2, '--mmdb', mmdb_a, '--tag', tag_a, '--chunks-per-run', '1')
        ok_partial = rc == 0 and 'partial' in out
        con = sqlite3.connect(db2)
        con.execute("UPDATE meta SET value='deadbeef:1' WHERE key='chunk_000'")
        con.commit()
        con.close()
        rc, out = sync(db2, '--mmdb', mmdb_a, '--tag', tag_a, '--chunks-per-run', '1')
        check('tampered chunk marker rejected', ok_partial and rc == 1 and 'marker mismatch' in out,
              f'rc={rc}')

        # pinned-tag override guard (offline mode must not download)
        if len(tagged) >= 2:
            rc, out = sync(db2, '--mmdb', mmdb_b, '--tag', tag_b, '--chunks-per-run', '1')
            check('pinned bootstrap rejects mismatched offline override',
                  rc == 1 and 'pinned' in out, f'rc={rc}')
    else:
        print('SKIP  data-dependent pipeline tests (no tmp/mm/*.mmdb)')

    # whole-file atomicity of SqliteD1.execute_sql (mirrors D1 --file, probe M7)
    sys.path.insert(0, ROOT)
    from geoip_sync import SqliteD1  # noqa: E402
    atom_db = os.path.join(WORK, 'atomic.sqlite')
    reset(atom_db)
    d1 = SqliteD1(atom_db)
    d1.execute_sql('CREATE TABLE t (k INTEGER PRIMARY KEY, v TEXT);')
    try:
        d1.execute_sql("INSERT INTO t VALUES (1,'a');\nTHIS IS A SYNTAX ERROR;\n")
        rolled = False
    except sqlite3.Error:
        rolled = True
    rows = d1.query('SELECT COUNT(*) AS c FROM t')
    d1.close()
    check('sqlite stand-in: mid-file failure rolls back whole file',
          rolled and rows[0]['c'] == 0, f'raised={rolled} survivors={rows[0]["c"]}')

    # pathguard confinement
    from pathguard import validated_path  # noqa: E402
    escaped = nulled = False
    try:
        validated_path('../outside.txt')
    except ValueError:
        escaped = True
    try:
        validated_path('tmp/x\x00y')
    except ValueError:
        nulled = True
    check('pathguard rejects escape and NUL', escaped and nulled,
          f'escape={escaped} nul={nulled}')

    # free-plan chunks-per-run guard (must fail before any network access)
    p = subprocess.run([PY, os.path.join(ROOT, 'geoip_sync.py'),
                        '--db', 'geoip_test', '--chunks-per-run', '2'],
                       cwd=ROOT, capture_output=True, text=True)
    check('free-plan guard rejects chunks-per-run > 1',
          p.returncode == 1 and 'free plan' in p.stderr, f'rc={p.returncode}')

    fails = [r for r in results if not r[1]]
    print(f'\n{len(results) - len(fails)}/{len(results)} passed')
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())