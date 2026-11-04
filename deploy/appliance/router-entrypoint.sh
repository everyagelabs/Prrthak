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
    # Older offline updaters retain the installed router configuration. Add
    # forwarding to its local routes at startup without changing that file.
    # Keep the router's certificate-verified health checks on the TLS ports.
    umask 077
    config=$(mktemp /tmp/prthak-haproxy.XXXXXX)
    awk '
        /^[[:blank:]]+server[[:blank:]]+local[[:blank:]]+controller:878[789][[:blank:]]/ {
            port = $3
            sub(/^controller:/, "", port)
            sub(/controller:878[789]/, "controller:" (10000 + port) " send-proxy-v2 port " port)
        }
        { print }
    ' /config/haproxy.cfg > "$config"
    set -- haproxy -W -db -f "$config"
fi

exec docker-entrypoint.sh "$@"
