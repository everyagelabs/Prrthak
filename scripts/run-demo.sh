#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
exec "${PYTHON:-python3}" -m controller --demo --listen "${SEG_DEMO_LISTEN:-127.0.0.1:8787}" --data-dir .local/demo
