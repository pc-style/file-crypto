#!/bin/bash
set -euo pipefail

# Maintenance script engineering-maintenance.sh

log() { echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') $1"; }
log 'Starting weekly maintenance'
systemctl stop app-web.service
rm -rf /srv/cache/*
pg_dump --format=custom core_production > /var/backups/core-production.dump
systemctl start app-web.service
log 'Maintenance complete'
