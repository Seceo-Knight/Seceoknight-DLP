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
#   curl -fsSL https://raw.githubusercontent.com/Seceo-Knight/Seceoknight-DLP/master/update.sh | sudo INSTALL_DIR=/opt/seceoknight bash
#
set -euo pipefail

# ─── Configuration ────────────────────────────────────────────────────
GITHUB_REPO="Seceo-Knight/Seceoknight-DLP"
# Default branch fixed to "master" -- that's the repo's actual active
# branch (confirmed via `git branch -vv` / .git/config: local tracks
# origin/master, and all recent commits live there). The old "main"
# default silently 404'd on files that only exist on master (e.g.
# nginx/nginx.conf), and -- more importantly -- both CI workflows
# (build-and-push.yml, ci.yml) only triggered on pushes to "main", so
# pushes to master never rebuilt the ghcr.io images this script pulls.
# Both workflows now also trigger on master; this default keeps the
# raw-file re-sync consistent with that.
GITHUB_BRANCH="${GITHUB_BRANCH:-master}"
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

# ─── 1.5 Guard against the disk filling up before we pull more images ──
# Every update re-tags "latest" to a new image digest, which leaves the
# PREVIOUS digest dangling (untagged, but still on disk) -- `docker compose
# pull` alone never cleans these up. Left unattended across enough updates
# this silently eats the entire disk: hit in production, where dangling
# image layers alone had grown to 24GB/38GB (63% of the whole root
# filesystem) with zero warning, until MongoDB's WiredTiger engine got
# "No space left on device" mid-write and hard-crashed (WT_PANIC), taking
# the update down with it. Proactively prune here, before pulling anything
# new, so a long-neglected server doesn't run out of room for this update's
# own image pull.
AVAIL_KB=$(df -Pk "${INSTALL_DIR}" | awk 'NR==2 {print $4}')
AVAIL_GB=$((AVAIL_KB / 1024 / 1024))
if [ "${AVAIL_GB}" -lt 5 ]; then
    c_yellow "[!] Only ${AVAIL_GB}GB free on the filesystem holding ${INSTALL_DIR}."
    say "Pruning unused Docker images to free space before pulling..."
    docker image prune -f || true
    NEW_AVAIL_KB=$(df -Pk "${INSTALL_DIR}" | awk 'NR==2 {print $4}')
    say "Free space now: $((NEW_AVAIL_KB / 1024 / 1024))GB"
fi

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

# ─── 4.5. Repackage & republish the browser extension ──────────────────
# Gap found September 2026, running this script for real: install.sh
# packages the browser extension (agents/browser-extension/ -> a signed
# .crx in server/extension_dist/, served by the running manager container,
# force-installed to endpoints via ExtensionInstallForcelist -- see
# install.sh's own step 8c comment and scripts/pack-extension.py) exactly
# ONCE, at initial install. This script had NO equivalent step at all --
# every extension-side fix committed to the repo (background.js,
# web-activity.js, a manifest.json version bump, ...) was completely
# invisible to every managed endpoint no matter how many times `git push`
# + `sudo bash update.sh` ran, because nothing here ever re-packaged and
# re-published the .crx. The server just kept serving whatever version was
# live at first install, forever, silently -- there is no error anywhere
# in this chain, it looks like a successful update every time. Confirmed
# live: an endpoint stuck on version 1.0.9 after several rounds of exactly
# that sequence, with newer fixes already sitting unpublished in the repo.
#
# Fixed here the same way install.sh does it: since "no source code is
# ever placed on the production server" is this deployment's whole design
# (see install.sh's own framing), the extension's small source tree is
# fetched into a TEMP directory, packaged, and the temp clone deleted
# immediately after -- only the packaged output (server/extension_dist/)
# and the persistent signing key (/etc/seceoknightdlp/extension-signing.pem
# -- reused, never regenerated, since a NEW key would make every endpoint
# see a completely different extension) remain on disk afterward.
#
# Entirely best-effort / non-fatal, same posture as install.sh's version --
# a server that can't (re)package the extension must never fail the rest
# of the update over it.
say "Repackaging the browser extension for force-install"
if command -v git >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
    if ! python3 -m pip show cryptography >/dev/null 2>&1; then
        say "Installing the 'cryptography' package"
        python3 -m pip install --quiet cryptography --break-system-packages >/dev/null 2>&1 \
            || python3 -m pip install --quiet cryptography >/dev/null 2>&1 \
            || c_yellow "[!] Could not install 'cryptography' -- skipping extension repackaging (non-fatal)"
    fi
    if python3 -m pip show cryptography >/dev/null 2>&1; then
        EXT_TMP="$(mktemp -d)"
        trap 'rm -rf "${EXT_TMP}"' EXIT
        if git clone --quiet --depth 1 --branch "${GITHUB_BRANCH}" \
                "https://github.com/${GITHUB_REPO}.git" "${EXT_TMP}/repo" 2>/dev/null \
            && [ -f "${EXT_TMP}/repo/scripts/pack-extension.py" ]; then
            HOST_IP_FOR_EXT="$(hostname -I 2>/dev/null | awk '{print $1}' || echo localhost)"
            if python3 "${EXT_TMP}/repo/scripts/pack-extension.py" \
                --out "${INSTALL_DIR}/server/extension_dist" \
                --server "http://${HOST_IP_FOR_EXT}"; then
                say "Browser extension repackaged and republished"
            else
                c_yellow "[!] Extension repackaging failed (non-fatal) -- run it manually later:"
                c_yellow "    git clone https://github.com/${GITHUB_REPO}.git && cd Seceoknight-DLP"
                c_yellow "    python3 scripts/pack-extension.py --out ${INSTALL_DIR}/server/extension_dist --server http://<this-server>"
            fi
        else
            c_yellow "[!] Could not fetch the extension source -- skipping (non-fatal, same manual command as above)"
        fi
        rm -rf "${EXT_TMP}"
        trap - EXIT
    fi
else
    c_yellow "[!] git or python3 unavailable -- skipping extension repackaging (non-fatal)"
    c_yellow "    Install them and run manually later:"
    c_yellow "    git clone https://github.com/${GITHUB_REPO}.git && cd Seceoknight-DLP"
    c_yellow "    python3 scripts/pack-extension.py --out ${INSTALL_DIR}/server/extension_dist --server http://<this-server>"
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
    echo
    # ─── 6. Routine cleanup ─────────────────────────────────────────────
    # This update's own containers are confirmed healthy above, so the
    # image digest(s) they replaced are now safely unused. Prune them
    # here, every time, so dangling layers never get the chance to build
    # up to a disk-filling problem again -- rather than relying on someone
    # noticing and running this by hand after the fact.
    say "Pruning superseded image layers"
    docker image prune -f || true
else
    c_red "[!] API did not come up healthy after the update."
    c_red "Check:"
    c_red "  docker compose -f ${COMPOSE_FILE} logs manager"
    c_red "  docker compose -f ${COMPOSE_FILE} logs nginx"
    exit 1
fi
