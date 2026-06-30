#!/bin/sh
set -eu

CRONTAB_DIR="${CRONTAB_DIR:-/home/vhc/crontabs}"

if [ -n "${CRON_SCHEDULE:-}" ]; then
    mkdir -p "$CRONTAB_DIR"
    echo "$CRON_SCHEDULE python /app/vhc_simplifier.py $*" > "$CRONTAB_DIR/vhc"
    exec busybox crond -f -l 8 -L /dev/stdout -c "$CRONTAB_DIR"
else
    exec python /app/vhc_simplifier.py "$@"
fi
