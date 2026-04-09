#!/bin/bash
set -e

CAPE_ROOT=/opt/CAPEv2

# CAPEv2's configparser imports every ENV value into the config,
# so no_proxy/NO_PROXY case conflicts can trigger DuplicateOptionError
# Clear all proxy-related environment variables
unset no_proxy NO_PROXY http_proxy HTTP_PROXY https_proxy HTTPS_PROXY

# Start MongoDB
echo "[entrypoint] Starting MongoDB..."
mongod --fork --logpath /var/log/mongodb.log --dbpath /var/lib/mongodb --bind_ip 127.0.0.1

# Start libvirtd (KVM management)
echo "[entrypoint] Starting libvirtd..."
mkdir -p /run/libvirt
libvirtd -d 2>/dev/null || true

# Fix permissions
chown -R cape:cape ${CAPE_ROOT}/storage ${CAPE_ROOT}/log 2>/dev/null || true

# Run database migrations
echo "[entrypoint] Running CAPE migrations..."
cd ${CAPE_ROOT}
sudo -u cape ${CAPE_ROOT}/venv/bin/python3 ${CAPE_ROOT}/utils/community.py -waf 2>/dev/null || true

echo "[entrypoint] Starting CAPEv2 services via supervisor..."
exec /usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf
