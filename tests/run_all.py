#!/usr/bin/env python3
"""Offline regression orchestrator — no Cloudflare credentials required.

Steps:
  1. tsc --noEmit                     (worker typecheck)
  2. tests/pipeline_tests.py          (sync state machine + guards + probes)
  3. tests/worker_tests.py            (endpoint battery against wrangler dev,
                                       incl. a low-rate-limit second instance)

Usage:
  python tests/run_all.py [--skip-worker] [--skip-pipeline]

Everything runs locally: D1 is the miniflare sqlite stand-in seeded from
migrations/0002 + tests/seed.sql; upstream DNS is the real 1.1.1.1/dns.google
(reachable from CI runners and dev machines alike).
"""
import argparse
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
NPX = 'npx.cmd' if os.name == 'nt' else 'npx'
LOG_DIR = os.path.join(ROOT, 'tmp', 'test_logs')


def run(cmd, **kw):
    print('+', ' '.join(str(c) for c in cmd), flush=True)
    return subprocess.run(cmd, cwd=ROOT, **kw)


def binding_name():
    with open(os.path.join(ROOT, 'wrangler.toml'), encoding='utf-8') as f:
        m = re.search(r'^database_name\s*=\s*"([^"]+)"', f.read(), re.M)
    if not m:
        raise SystemExit('cannot read database_name from wrangler.toml')
    return m.group(1)


def wait_ready(port, log_path, timeout=90):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f'http://127.0.0.1:{port}/health', timeout=3) as r:
                if r.status == 200:
                    return True
        except (urllib.error.URLError, OSError, TimeoutError):
            pass
        time.sleep(1)
    print(f'--- server on :{port} never became ready; log tail:', file=sys.stderr)
    try:
        with open(log_path, encoding='utf-8', errors='replace') as f:
            print(''.join(f.readlines()[-25:]), file=sys.stderr)
    except OSError:
        pass
    return False


def free_port():
    """Ask the OS for an unused port (avoids runner-image/service collisions
    and races between our own two wrangler instances)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def start_dev(port, inspector_port, log_path, extra=()):
    log = open(log_path, 'w', encoding='utf-8')
    kwargs = {}
    if os.name == 'nt':
        kwargs['creationflags'] = subprocess.CREATE_NEW_PROCESS_GROUP
    proc = subprocess.Popen(
        [NPX, 'wrangler', 'dev', '--port', str(port), '--ip', '127.0.0.1',
         '--inspector-port', str(inspector_port), *extra],
        cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, **kwargs)
    return proc, log


def stop_dev(proc, log):
    if os.name == 'nt':
        subprocess.run(['taskkill', '/PID', str(proc.pid), '/T', '/F'],
                       capture_output=True)
    else:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    log.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--skip-worker', action='store_true')
    ap.add_argument('--skip-pipeline', action='store_true')
    args = ap.parse_args()
    os.makedirs(LOG_DIR, exist_ok=True)
    failures = []

    # 1. typecheck
    p = run([NPX, 'tsc', '--noEmit'])
    if p.returncode != 0:
        failures.append('typecheck')

    # 2. pipeline
    if not args.skip_pipeline:
        p = run([PY, os.path.join(ROOT, 'tests', 'pipeline_tests.py')])
        if p.returncode != 0:
            failures.append('pipeline')
    else:
        print('SKIP  pipeline tests (--skip-pipeline)')

    # 3. worker endpoints
    if not args.skip_worker:
        db = binding_name()
        # Fresh, isolated persistence per run: the Cache API and D1 are
        # disk-backed, so reusing .wrangler/state would let a previous run's
        # L2 entries contaminate cache-counter and TTL-aging assertions.
        persist_main = os.path.join(LOG_DIR, 'persist-main')
        persist_rate = os.path.join(LOG_DIR, 'persist-rate')
        for d in (persist_main, persist_rate):
            shutil.rmtree(d, ignore_errors=True)
        p = run([NPX, 'wrangler', 'd1', 'execute', db, '--local', '-y',
                 '--persist-to', persist_main,
                 '--file', 'migrations/0002_merged_pk_schema.sql'],
                capture_output=True, text=True, encoding='utf-8', errors='replace')
        if p.returncode != 0:
            print(p.stdout[-800:], p.stderr[-800:], file=sys.stderr)
            failures.append('seed-schema')
        p = run([NPX, 'wrangler', 'd1', 'execute', db, '--local', '-y',
                 '--persist-to', persist_main,
                 '--file', 'tests/seed.sql'],
                capture_output=True, text=True, encoding='utf-8', errors='replace')
        if p.returncode != 0:
            print(p.stdout[-800:], p.stderr[-800:], file=sys.stderr)
            failures.append('seed-data')

        servers = []
        if not failures:
            # Sequential startup: the first instance must be ready before the
            # second starts (simultaneous wrangler dev startup races on the
            # shared dev registry / ports on CI runners).
            main_port, rate_port = free_port(), free_port()
            main_proc, main_log = start_dev(main_port, free_port(),
                                            os.path.join(LOG_DIR, 'dev-main.log'),
                                            extra=('--persist-to', persist_main))
            servers.append((main_proc, main_log))
            if wait_ready(main_port, os.path.join(LOG_DIR, 'dev-main.log')):
                # Separate persistence dir: two workerd processes cannot share
                # one local D1 sqlite file (SQLITE_BUSY). The rate-limit
                # instance needs no geo seed — /resolve and /health work
                # without D1 data.
                rate_proc, rate_log = start_dev(rate_port, free_port(),
                                                os.path.join(LOG_DIR, 'dev-rate.log'),
                                                extra=('--var', 'RATE_LIMIT_PER_10S:3',
                                                       '--persist-to', persist_rate))
                servers.append((rate_proc, rate_log))
                if wait_ready(rate_port, os.path.join(LOG_DIR, 'dev-rate.log')):
                    env = {**os.environ, 'BASE': f'http://127.0.0.1:{main_port}',
                           'RATE_BASE': f'http://127.0.0.1:{rate_port}'}
                    p = subprocess.run([PY, os.path.join(ROOT, 'tests', 'worker_tests.py')],
                                       cwd=ROOT, env=env)
                    if p.returncode != 0:
                        failures.append('worker-endpoints')
                else:
                    failures.append('dev-server-startup')
            else:
                failures.append('dev-server-startup')
            if 'dev-server-startup' in failures and os.name != 'nt':
                subprocess.run(['ss', '-tlnp'], capture_output=False)
        for proc, log in servers:
            stop_dev(proc, log)
    else:
        print('SKIP  worker tests (--skip-worker)')

    print('\n========================================')
    if failures:
        print(f'REGRESSION FAILED: {", ".join(failures)}')
        return 1
    print('ALL REGRESSION SUITES PASSED')
    return 0


if __name__ == '__main__':
    sys.exit(main())