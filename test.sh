#!/bin/bash
# Smoke test against a DEPLOYED DoH endpoint with real TLS validation
# (certificate checks stay enabled — Sonar S4830). Usage:
#   DOH_URL=https://doh.<your-subdomain>.workers.dev/dns-query ./test.sh
#
# Local testing does not need this script: tests/run_all.py exercises
# `wrangler dev` over plain HTTP (no TLS, no validation bypass).
set -euo pipefail
DOH_URL="${DOH_URL:?set DOH_URL to your deployed DoH endpoint, e.g. https://doh.<subdomain>.workers.dev/dns-query}"
curl --doh-url "$DOH_URL" "https://www.aliyun.com" -I -4 -v