#!/usr/bin/env bash
#
# SeceoKnight DLP — Update script for an EXISTING server install.
#
# Fixes a real production issue hit while operating this stack: running
# the "obvious" update command --
#
#   docker compose pull && docker compose up -d
#
# -- recreates the manager/dashboard/celery containers with brand-new
# internal Docker IPs, but leaves the long-running nginx container
# untouched. nginx resolves the "manager"/"dashboard" service names to a
# container IP and (depending on how long it's been running / when it last
# reloaded) can keep using the OLD IP, so every request 502s until nginx is
# separately restarted. This is exactly what happened during a real update:
# the API and dashboard were both healthy, but nginx was still proxying to
# a dead IP behind the scenes, and the failure surfaced as a misleading
# "Invalid email or password" in the UI instead of an obvious connectivity
# error.
#
# A second, separate gap: install.sh only ever downloads
# docker-compose.prod.yml and nginx/nginx.conf ONCE, on first install.
# `docker compose pull` only refreshes container *images* -- it never
# re-fetches those two host-side files. So config-level fixes committed to
# the repo (including the nginx resolver-based upstream fix that is
# *supposed* to prevent the exact problem above) never reach a server that
# was installed before that fix landed, unless someone re-downloads the
# files by hand.
#
# This script closes both gaps: it re-syncs the config files (backing up
# anything already there first, in case it was hand-edited), pulls new
# images, recreates nginx alongside the backend services every single time
# regardless of whether nginx's own image changed, and runs pending
# database migrations -- the same sequence this repo's own operators had to
# work out by hand during a live incident.
#
# Usage:
#   cd /opt/seceoknight && sudo bash update.sh
#
# Or, if you don't already have this file locally:
#   curl -fsSL https://raw.githubusercontent.com/Seceo-Knight/Seceoknight-DLP/main/update.sh | sudo INSTALL_DIR=/opt/seceoknight bash
#
set -euo pipefail

# ─── Configuration ────────────────────────────────────────────────────
GITHUB_REPO="Seceo-Knight/Seceoknight-DLP"
GITHUB_BRANCH="${GITHUB_BRANCH:-main}"
RAW_BASE="https://raw.githubusercontent.com/${GITHUB_REPO}/${GITHUB_BRANCH}"
INSTALL_DIR="${INSTALL_DIR:-$(pwd)}"
COMPOSE_FILE="docker-compose.prod.yml"

# ─── Helpers ──────────────────────────────────────────────────────────
c_blue()   { printf "\033[1;34m%s\033[0m\n" "$*"; }
c_green()  { printf "\033[1;32m%s\033[0m\n" "$*"; }
c_yellow() { printf "\033[1;33m%s\033[0m\n" "$*"; }
c_red()    { printf "\033[1;31m%s\033[0m\n" "$*" >&2; }
say()      { printf "[+] %s\n" "$*"; }
die()      { c_red "[FATAL] $*"; exit 1; }

if [ "$(id -u)" -ne 0 ]; then
    die "This script must be run as root (sudo)."
fi

if [ ! -f "${INSTALL_DIR}/${COMPOSE_FILE}" ]; then
    die "${INSTALL_DIR}/${COMPOSE_FILE} not found. Run this from your install directory (default /opt/seceoknight), or set INSTALL_DIR=/path/to/install bash update.sh."
fi

cd "${INSTALL_DIR}"
c_blue "================================================================"
c_blue "  SeceoKnight DLP — Update"
c_blue "================================================================"
say "Install dir: ${INSTALL_DIR}"
echo

# ─── 1. Re-sync config files that install.sh only ever downloads once ──
backup_and_fetch() {
    local rel_path="$1"
    local dest="${INSTALL_DIR}/${rel_path}"
    if [ -f "${dest}" ]; then
        local backup="${dest}.bak.$(date +%Y%m%d%H%M%S)"
        cp "${dest}" "${backup}"
        echo "    (existing file backed up to $(basename "${backup}"))"
    fi
    mkdir -p "$(dirname "${dest}")"
    curl -fsSL "${RAW_BASE}/${rel_path}" -o "${dest}"
}

say "Re-syncing ${COMPOSE_FILE} from ${GITHUB_BRANCH}"
backup_and_fetch "${COMPOSE_FILE}"

say "Re-syncing nginx/nginx.conf from ${GITHUB_BRANCH}"
backup_and_fetch "nginx/nginx.conf"

c_yellow "  If you hand-edited either file (custom domain, extra nginx locations,"
c_yellow "  non-default ports, etc.), diff the .bak file against the new one and"
c_yellow "  reapply your changes before continuing:"
c_yellow "    diff ${COMPOSE_FILE}.bak.* ${COMPOSE_FILE}"
c_yellow "    diff nginx/nginx.conf.bak.* nginx/nginx.conf"
echo

# ─── 2. Pull new images ─────────────────────────────────────────────────
say "Pulling latest images from ghcr.io/${GITHUB_REPO}"
docker compose -f "${COMPOSE_FILE}" pull

# ─── 3. Recreate backend services AND nginx together ───────────────────
# `docker compose up -d` alone only recreates containers whose image or
# config actually changed. nginx's own image rarely changes on a routine
# update, so a bare `up -d` here would recreate manager/dashboard (new
# internal IPs) while leaving nginx running unchanged against the old
# ones -- exactly the bug this script exists to prevent. Force nginx into
# the recreate list every time, unconditionally.
say "Recreating services, including nginx (so it never proxies to a stale container IP)"
docker compose -f "${COMPOSE_FILE}" up -d --force-recreate \
    manager dashboard celery-worker celery-beat nginx

# ─── 4. Apply any new database migrations ───────────────────────────────
say "Waiting for the manager container to accept exec commands"
for i in $(seq 1 60); do
    if docker exec seceoknight-manager true >/dev/null 2>&1; then
        break
    fi
    sleep 2
done

say "Applying database migrations (alembic upgrade head)"
if ! docker exec seceoknight-manager alembic upgrade head; then
    c_red "[!] Migration failed. Check: docker compose -f ${COMPOSE_FILE} logs manager"
    exit 1
fi

# ─── 5. Health check ─────────────────────────────────────────────────────
say "Waiting for the API to come up via nginx (max ~2 minutes)"
for i in $(seq 1 60); do
    if curl -fsSk https://localhost/api/v1/health >/dev/null 2>&1; then
        break
    fi
    sleep 2
    printf "."
done
echo

if curl -fsSk https://localhost/api/v1/health >/dev/null 2>&1; then
    echo
    c_green "================================================================"
    c_green "  Update complete — API is healthy"
    c_green "================================================================"
    docker compose -f "${COMPOSE_FILE}" ps
else
    c_red "[!] API did not come up healthy after the update."
    c_red "Check:"
    c_red "  docker compose -f ${COMPOSE_FILE} logs manager"
    c_red "  docker compose -f ${COMPOSE_FILE} logs nginx"
    exit 1
fi
