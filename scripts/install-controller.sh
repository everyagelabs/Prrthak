#!/bin/sh
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
release_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
python_bin=${PRTHAK_INSTALL_PYTHON:-python3}
if ! command -v "$python_bin" >/dev/null 2>&1; then
  echo 'Prṛthak installer requires Python 3.9+ and Docker Engine with Compose v2.' >&2
  exit 1
fi
exec "$python_bin" "$release_root/deploy/appliance/node_manager.py" install --release-root "$release_root" "$@"
