#!/bin/sh
# Parse only. Does not start/reload HAProxy or connect to controllers.
set -eu
if [ "$#" -ne 1 ]; then
  echo 'Usage: validate-haproxy.sh /path/to/reviewed-haproxy.cfg' >&2
  exit 2
fi
if ! command -v haproxy >/dev/null 2>&1; then
  echo 'Native HAProxy binary unavailable: this helper cannot validate your target package here.' >&2
  echo 'Install an approved HAProxy 2.8+ OpenSSL build, provide the public CA file, then run: haproxy -c -f CONFIG' >&2
  exit 2
fi
exec haproxy -c -f "$1"
