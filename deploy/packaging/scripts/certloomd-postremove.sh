#!/bin/sh
# /etc/certloom and the certloom user are left in place; the data lives in
# PostgreSQL.
set -e

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
