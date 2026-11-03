#!/bin/sh
# One verified GUI-configured installer for every supported endpoint family.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset LD_LIBRARY_PATH LD_PRELOAD ENV BASH_ENV
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec /bin/sh "$SCRIPT_DIR/install-agent-linux.sh" auto "$@"
