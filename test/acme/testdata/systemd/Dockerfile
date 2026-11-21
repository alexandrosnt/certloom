# Debian with systemd as PID 1 and nginx, for testing the certloom-agent package.
# Run with: --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock
FROM debian:13.2-slim
ENV container=docker DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends systemd systemd-sysv nginx \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/nginx/sites-enabled/default \
 && systemctl disable nginx.service \
 && systemctl mask getty.target console-getty.service systemd-logind.service \
      systemd-udevd.service systemd-udev-trigger.service systemd-firstboot.service \
      systemd-hwdb-update.service systemd-remount-fs.service
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
