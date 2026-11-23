#!/bin/sh
# Runs after install and upgrade (deb and rpm). Creates the certloom user and
# migrates and restarts a running certloomd on upgrade. A fresh install is
# configured and started by "certloomd setup".
set -e

if command -v systemd-sysusers >/dev/null 2>&1; then
    systemd-sysusers certloomd.conf
elif ! getent passwd certloom >/dev/null; then
    useradd --system --home-dir /var/lib/certloom --no-create-home \
        --shell /usr/sbin/nologin --comment "certloom control plane" certloom
fi

mkdir -p /etc/certloom/tls
chown root:certloom /etc/certloom/certloomd.env /etc/certloom/tls
chmod 0640 /etc/certloom/certloomd.env
chmod 0750 /etc/certloom/tls

if [ -f /etc/certloom/migrate.env ]; then
    # Set up by "certloomd setup": migrate before the new version starts.
    (set -a; . /etc/certloom/migrate.env; certloomd migrate) ||
        echo "certloomd: migrations failed; run 'sudo certloomd setup' to retry" >&2
else
    echo "certloomd installed. Run 'sudo certloomd setup' to configure and start it."
fi

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl try-restart certloomd.service >/dev/null 2>&1 || true
fi
exit 0
