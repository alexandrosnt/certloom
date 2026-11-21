#!/bin/sh
# Runs after install and upgrade (deb and rpm). The service is not enabled or
# started here: the agent has to be enrolled first. On upgrade a running agent
# is restarted so it picks up the new binary.
set -e

mkdir -p /var/lib/certloom-agent /etc/certloom/live
chmod 0700 /var/lib/certloom-agent

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl try-restart certloom-agent.service >/dev/null 2>&1 || true
fi
exit 0
