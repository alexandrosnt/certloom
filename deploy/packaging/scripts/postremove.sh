#!/bin/sh
# /var/lib/certloom-agent (enrollment identity and private keys) and /etc/certloom are
# left in place; remove them by hand to decommission the host.
set -e

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
