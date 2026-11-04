#!/bin/sh
set -eu

# The older appliance updater starts both containers with restart disabled.
# Wait for the local backend's Docker DNS record before HAProxy parses it.
if [ "$#" -eq 5 ] && [ "$1" = haproxy ] && [ "$2" = -W ] && [ "$3" = -db ] &&
   [ "$4" = -f ] && [ "$5" = /config/haproxy.cfg ]; then
    attempts=0
    until timeout 2 getent hosts controller >/dev/null 2>&1; do
        attempts=$((attempts + 1))
        if [ "$attempts" -ge 20 ]; then
            echo 'Prthak router could not resolve the local controller through Docker DNS' >&2
            exit 1
        fi
        sleep 1
    done
fi

exec docker-entrypoint.sh "$@"
