#!/bin/sh
# Stop and disable the service on removal, not on upgrade.
# deb passes "remove"; rpm passes 0 when the last version is erased.
set -e

case "$1" in
    remove|0)
        if [ -d /run/systemd/system ]; then
            systemctl disable --now certloomd.service >/dev/null 2>&1 || true
        fi
        ;;
esac
exit 0
