#!/usr/bin/env python3
"""Endpoint regression battery for the DoH worker against `wrangler dev` (local).

Run via tests/run_all.py (starts/seeds/stops the server), or standalone:
    BASE=http://127.0.0.1:8787 python tests/worker_tests.py
    RATE_BASE=http://127.0.0.1:8788 python tests/worker_tests.py   # rate-limit instance

Upstream DNS (1.1.1.1 / dns.google) must be reachable from the dev machine.
"""
import base64
import json
import os
import random
import struct
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

BASE = os.environ.get('BASE', 'http://127.0.0.1:8787')
RATE_BASE = os.environ.get('RATE_BASE', '')
results = []


def check(label, cond, detail=''):
    results.append((label, bool(cond), detail))
    print(f"{'PASS' if cond else 'FAIL'}  {label}  {detail}")


def req(path, data=None, headers=None, method=None, base=None):
    r = urllib.request.Request((base or BASE) + path, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def dns_query(name, qtype=1, qid=0x1234):
    parts = name.rstrip('.').split('.') if name else ['']
    q = struct.pack('>HHHHHH', qid, 0x0100, 1, 0, 0, 0)
    for p in parts:
        q += bytes([len(p)]) + p.encode()
    return q + b'\x00' + struct.pack('>HH', qtype, 1)


def b64url(b):
    return base64.urlsafe_b64encode(b).decode().rstrip('=')


def parse_id(buf):
    return struct.unpack('>H', buf[:2])[0] if len(buf) >= 2 else None


def parse_flags(buf):
    return struct.unpack('>H', buf[2:4])[0] if len(buf) >= 4 else None


def stats():
    s, h, b = req('/stats')
    return json.loads(b)


def answer_ttls(buf):
    """Minimal walk: return TTLs of the answer section (compressed names ok)."""
    if len(buf) < 12:
        return []
    qd, an = struct.unpack('>HH', buf[4:8])
    off = 12

    def skip_name(o):
        if o < len(buf) and buf[o] & 0xC0 == 0xC0:
            return o + 2
        while o < len(buf) and buf[o] != 0:
            o += 1
        return o + 1

    for _ in range(qd):
        off = skip_name(off) + 4
    ttls = []
    for _ in range(an):
        off = skip_name(off)
        if off + 10 > len(buf):
            break
        ttls.append(struct.unpack('>I', buf[off + 4:off + 8])[0])
        dl = struct.unpack('>H', buf[off + 8:off + 10])[0]
        off += 10 + dl
    return ttls


# --- JSON API ---------------------------------------------------------------
s, h, b = req('/resolve?name=example.com&type=A')
j = json.loads(b) if s == 200 else {}
first_ttls = [a['TTL'] for a in (j.get('Answer') or [])]
check('resolve A example.com', s == 200 and j.get('Status') == 0 and j.get('Answer'),
      f'status={s} answers={len(j.get("Answer") or [])}')

s, h, b = req('/resolve?name=example.com.&type=A')
j = json.loads(b) if s == 200 else {}
check('resolve trailing-dot canonicalized', s == 200 and j.get('Status') == 0 and j.get('Answer'),
      f'status={s} answers={len(j.get("Answer") or [])}')

s, h, b = req('/resolve?name=example.com&type=MX')
check('resolve unsupported type -> 400', s == 400, f'status={s}')

s, h, b = req('/resolve?name=' + 'a' * 300 + '.com&type=A')
check('resolve over-long label -> 400', s == 400, f'status={s}')

s, h, b = req('/resolve?name=%E4%B8%AD%E6%96%87.example.com&type=A')
check('resolve non-ASCII -> 400 (punycode hint)', s == 400, f'status={s}')

s, h, b = req('/resolve?name=-bad.example.com&type=A')
check('resolve hyphen-edge label -> 400', s == 400, f'status={s}')

s, h, b = req('/resolve')
check('resolve missing name -> 400', s == 400, f'status={s}')

# --- DoH wire ---------------------------------------------------------------
q = dns_query('example.com', 1, 0x1234)
s, h, b = req('/dns-query?dns=' + b64url(q))
check('DoH GET b64url', s == 200 and h.get('Content-Type') == 'application/dns-message'
      and parse_id(b) == 0x1234 and parse_flags(b) & 0x8000,
      f'status={s} id={parse_id(b):#x} len={len(b)}')

q2 = dns_query('example.com', 1, 0xABCD)
s, h, b = req('/dns-query?dns=' + b64url(q2))
check('DoH GET cache-hit ID rewrite', s == 200 and parse_id(b) == 0xABCD,
      f'status={s} id={parse_id(b):#x}')

q3 = dns_query('example.org', 1, 0x0001)
std = base64.b64encode(q3).decode().rstrip('=')
s, h, b = req('/dns-query?dns=' + std.replace('+', '%2B').replace('/', '%2F'))
check('DoH GET std-base64', s == 200 and parse_id(b) == 0x0001, f'status={s}')

q4 = dns_query('www.aliyun.com', 1, 0x7777)
s, h, b = req('/client-ip/223.5.5.5/client-country/CN/alternative-ip/8.8.8.8/dns-query',
              data=q4, headers={'Content-Type': 'application/dns-message'})
check('DoH POST legacy dual-IP', s == 200 and parse_id(b) == 0x7777,
      f'status={s} id={parse_id(b):#x} len={len(b)}')

# --- malformed / hardening --------------------------------------------------
s, h, b = req('/dns-query', data=b'\x00\x01', headers={'Content-Type': 'application/dns-message'})
check('malformed short -> 400', s == 400, f'status={s}')

bad = struct.pack('>HHHHHH', 1, 0x0100, 0, 0, 0, 0)
s, h, b = req('/dns-query', data=bad, headers={'Content-Type': 'application/dns-message'})
check('malformed qdcount=0 -> 400', s == 400, f'status={s}')

bad = struct.pack('>HHHHHH', 1, 0x0100, 1, 0, 0, 0) + b'\xc0\x0c' + struct.pack('>HH', 1, 1)
s, h, b = req('/dns-query', data=bad, headers={'Content-Type': 'application/dns-message'})
check('malformed pointer-in-question -> 400', s == 400, f'status={s}')

bad = struct.pack('>HHHHHH', 1, 0x0100, 1, 0, 0, 0) + b'\x07example'
s, h, b = req('/dns-query', data=bad, headers={'Content-Type': 'application/dns-message'})
check('malformed truncated name -> 400', s == 400, f'status={s}')

bad = struct.pack('>HHHHHH', 1, 0x8100, 1, 0, 0, 0) + b'\x07example\x03com\x00' + struct.pack('>HH', 1, 1)
s, h, b = req('/dns-query', data=bad, headers={'Content-Type': 'application/dns-message'})
check('QR=1 posted as query -> 400', s == 400, f'status={s}')

s, h, b = req('/dns-query', data=b'\x00' * 65536, headers={'Content-Type': 'application/dns-message'})
check('oversized POST body -> 413', s == 413, f'status={s}')

s, h, b = req('/debug/ip/8.8.8.8')
check('debug/ip no token -> 404', s == 404, f'status={s}')

q5 = dns_query('example.net', 1, 0x5555)
s, h, b = req('/client-ip/not-an-ip/dns-query', data=q5,
              headers={'Content-Type': 'application/dns-message'})
check('garbage client-ip -> still 200', s == 200, f'status={s}')

# --- IPv6 + cache-key normalization -----------------------------------------
q6 = dns_query('example.com', 28, 0x6666)
s, h, b = req('/client-ip/2001:db8::1/dns-query', data=q6,
              headers={'Content-Type': 'application/dns-message'})
check('IPv6 client-ip AAAA', s == 200 and parse_id(b) == 0x6666, f'status={s} len={len(b)}')

st0 = stats()
q7 = dns_query('example.com', 28, 0x6667)
s, h, b = req('/client-ip/2001:db8:0:0:0:0:0:1/dns-query', data=q7,
              headers={'Content-Type': 'application/dns-message'})
st1 = stats()
miss_delta = st1['dnsCache']['cacheMisses'] - st0['dnsCache']['cacheMisses']
check('IPv6 expanded form shares cache entry', s == 200 and miss_delta == 0,
      f'status={s} cacheMisses delta={miss_delta}')

st0 = stats()
q8 = dns_query('EXAMPLE.COM', 1, 0x6668)
s, h, b = req('/dns-query?dns=' + b64url(q8))
st1 = stats()
miss_delta = st1['dnsCache']['cacheMisses'] - st0['dnsCache']['cacheMisses']
check('case-varied query shares cache entry', s == 200 and miss_delta == 0,
      f'status={s} cacheMisses delta={miss_delta}')

# --- NXDOMAIN + negative cache ----------------------------------------------
# Random name guarantees a cache miss even if storage were reused.
nx_name = f'nonexistent-zzz-{random.randint(100000, 999999)}.invalid'
s, h, b = req(f'/resolve?name={nx_name}&type=A')
j = json.loads(b) if s == 200 else {}
check('NXDOMAIN JSON Status=3 (RCODE, not opcode)', s == 200 and j.get('Status') == 3,
      f'status={s} Status={j.get("Status")}')
st = stats()
check('negativeCached counter wired', st['dnsCache'].get('negativeCached', 0) >= 1,
      f'negativeCached={st["dnsCache"].get("negativeCached")}')

# --- TTL aging on cache hit --------------------------------------------------
if first_ttls:
    time.sleep(2.2)
    s, h, b = req('/resolve?name=example.com&type=A')
    j = json.loads(b) if s == 200 else {}
    later_ttls = [a['TTL'] for a in (j.get('Answer') or [])]
    check('cache hit ages answer TTLs', later_ttls and later_ttls[0] <= first_ttls[0] - 2,
          f'first={first_ttls[0]} later={later_ttls[0] if later_ttls else None}')
else:
    check('cache hit ages answer TTLs', False, 'no baseline TTL (first resolve failed)')

# --- single-flight dedup ------------------------------------------------------
st0 = stats()
tag = random.randint(100000, 999999)
sf_name = f'singleflight-{tag}.example.com'
qs = dns_query(sf_name, 1, 0x2000)
with ThreadPoolExecutor(max_workers=6) as pool:
    futures = [pool.submit(req, '/dns-query?dns=' + b64url(qs)) for _ in range(6)]
    sf_results = [f.result() for f in futures]
st1 = stats()
fetch_delta = st1['dnsCache']['upstreamFetches'] - st0['dnsCache']['upstreamFetches']
# With dedup: 1 fetch (or 2 if the staggered backup fired on a slow primary).
# Without dedup: >= 6. cacheMisses counts per request, so it is NOT the signal.
check('single-flight: 6 concurrent identical misses -> <=2 upstream fetches',
      all(r[0] == 200 for r in sf_results) and 1 <= fetch_delta <= 2,
      f'statuses={[r[0] for r in sf_results]} upstreamFetches delta={fetch_delta}')

# --- misc ---------------------------------------------------------------------
s, h, b = req('/dns-query', method='OPTIONS')
check('OPTIONS -> 204 + CORS incl debug header', s == 204
      and h.get('Access-Control-Allow-Origin') == '*'
      and 'x-debug-token' in (h.get('Access-Control-Allow-Headers') or ''),
      f'status={s}')

s, h, b = req('/dns-query', method='PUT')
check('PUT -> 405', s == 405, f'status={s}')

s, h, b = req('/health')
j = json.loads(b)
check('health: connected + d1Cooldown field', s == 200 and j.get('database') == 'connected'
      and 'd1Cooldown' in j, f'database={j.get("database")}')

s, h, b = req('/stats')
j = json.loads(b)
check('stats shape (negativeCached, rateLimited)', s == 200
      and 'negativeCached' in j.get('dnsCache', {}) and 'rateLimited' in j.get('requests', {}),
      f'dns={j.get("dnsCache")}')

# --- rate limiting (dedicated low-limit instance) ------------------------------
if RATE_BASE:
    codes = []
    for i in range(6):
        s, h, b = req(f'/resolve?name=example.com&type=A', base=RATE_BASE)
        codes.append(s)
    check('rate limit: 429 after bucket exhausted (limit=3/10s)',
          codes[:3] == [200, 200, 200] and 429 in codes[3:],
          f'codes={codes}')
    s, h, b = req('/health', base=RATE_BASE)
    check('rate limit does not apply to /health', s == 200, f'status={s}')
else:
    print('SKIP  rate-limit tests (RATE_BASE not set)')

fails = [r for r in results if not r[1]]
print(f'\n{len(results) - len(fails)}/{len(results)} passed')
sys.exit(1 if fails else 0)