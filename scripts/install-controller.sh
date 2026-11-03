#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
release_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
# The fixed bootstrap installs prerequisites and defaults to GUI configuration.
# node_manager.py owns application state, identity and service setup.
exec /bin/sh "$script_dir/install-prerequisites.sh" --release-root "$release_root" "$@"
