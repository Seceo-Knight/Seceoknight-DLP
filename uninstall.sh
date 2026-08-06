#!/usr/bin/env bash
#
# SeceoKnight DLP — Server uninstaller.
#
# Stops and removes the SeceoKnight DLP stack. By default it keeps your data
# (Postgres/Mongo/OpenSearch/Redis volumes) so you can reinstall over it. Pass
# --purge to also delete the volumes and the install directory — that is
# IRREVERSIBLE and wipes events, agents, policies and users.
#
# Ported from a comparable script in CyberSentinel-DLP (a competitor product)
# after finding SeceoKnight had no scripted teardown at all — the only
# alternative was an operator hand-typing `docker compose down -v`, which has
# no confirmation gate whatsoever. Added one thing beyond a straight port:
# --backup, since DLP audit/incident data may carry compliance retention
# requirements a generic product's uninstaller wouldn't need to consider.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Seceo-Knight/Seceoknight-DLP/main/uninstall.sh | sudo bash
#   curl -fsSL .../uninstall.sh | sudo bash -s -- --purge             # also delete all data
#   curl -fsSL .../uninstall.sh | sudo bash -s -- --purge --backup    # dump DBs first, then delete
#   sudo INSTALL_DIR=/srv/seceoknight bash uninstall.sh                # custom dir
#
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/seceoknight}"
COMPOSE_FILE="docker-compose.prod.yml"
PURGE=0
ASSUME_YES=0
BACKUP=0
for arg in "$@"; do
    case "$arg" in
        --purge) PURGE=1 ;;
        --yes|-y) ASSUME_YES=1 ;;
        --backup) BACKUP=1 ;;
        *) echo "Unknown option: $arg" >&2; exit 2 ;;
    esac
done

c_blue()   { printf "\033[1;34m%s\033[0m\n" "$*"; }
c_green()  { printf "\033[1;32m%s\033[0m\n" "$*"; }
c_yellow() { printf "\033[1;33m%s\033[0m\n" "$*"; }
c_red()    { printf "\033[1;31m%s\033[0m\n" "$*" >&2; }
say()      { printf "[+] %s\n" "$*"; }
die()      { c_red "[FATAL] $*"; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run as root (sudo)."

if [ "$BACKUP" -eq 1 ] && [ "$PURGE" -ne 1 ]; then
    c_yellow "[!] --backup only does anything alongside --purge (data volumes are kept"
    c_yellow "    either way without --purge, so there is nothing to back up before deleting)."
fi

c_blue "================================================================"
c_blue "  SeceoKnight DLP — Server Uninstaller"
c_blue "================================================================"
echo
say "Install dir: ${INSTALL_DIR}"
if [ "$PURGE" -eq 1 ]; then
    c_red   "Mode:        PURGE — containers, volumes (ALL DATA) and ${INSTALL_DIR} will be DELETED"
    [ "$BACKUP" -eq 1 ] && say "Backup:      Postgres + MongoDB will be dumped before deletion"
else
    say     "Mode:        stop & remove containers; data volumes are KEPT (use --purge to delete them)"
fi
echo

# Locate the compose file. Fall back to `docker compose ls` if the install dir
# was moved, so we can still bring the project down.
COMPOSE_PATH="${INSTALL_DIR}/${COMPOSE_FILE}"
ENV_PATH="${INSTALL_DIR}/.env"
if [ ! -f "$COMPOSE_PATH" ]; then
    c_yellow "[!] ${COMPOSE_PATH} not found."
    ALT="$(docker compose ls --all 2>/dev/null | awk '/seceoknight/ {print $NF; exit}')"
    if [ -n "${ALT:-}" ] && [ -f "$ALT" ]; then
        COMPOSE_PATH="$ALT"
        say "Using discovered compose file: $COMPOSE_PATH"
    else
        c_yellow "[!] No compose file found; will fall back to removing containers/volumes by name."
        COMPOSE_PATH=""
    fi
fi

# Confirmation gate for the destructive path.
if [ "$PURGE" -eq 1 ] && [ "$ASSUME_YES" -ne 1 ]; then
    c_red "This will PERMANENTLY DELETE all SeceoKnight DLP data on this host."
    printf "Type the word DELETE to proceed: "
    read -r reply </dev/tty || die "No terminal for confirmation; re-run with --yes to skip the prompt."
    [ "$reply" = "DELETE" ] || die "Aborted — nothing was changed."
fi

# Best-effort DB dump before a purge. Failure here does not abort the
# uninstall (an operator who explicitly typed DELETE has already accepted
# data loss) — it only warns, so a backup problem never blocks a teardown
# the operator asked for.
if [ "$PURGE" -eq 1 ] && [ "$BACKUP" -eq 1 ]; then
    BACKUP_DIR="/var/backups/seceoknight/$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    say "Backing up databases to ${BACKUP_DIR} ..."

    if [ -f "$ENV_PATH" ]; then
        # shellcheck disable=SC1090
        set -a; . "$ENV_PATH"; set +a
    fi

    if docker ps --format '{{.Names}}' | grep -qx "seceoknight-postgres"; then
        if docker exec seceoknight-postgres pg_dump -U "${POSTGRES_USER:-seceoknight}" "${POSTGRES_DB:-seceoknight}" \
            > "${BACKUP_DIR}/postgres.sql" 2>/dev/null; then
            say "  postgres.sql written ($(du -h "${BACKUP_DIR}/postgres.sql" | cut -f1))"
        else
            c_yellow "  [!] pg_dump failed — postgres NOT backed up"
            rm -f "${BACKUP_DIR}/postgres.sql"
        fi
    else
        c_yellow "  [!] seceoknight-postgres container not running — skipped"
    fi

    if docker ps --format '{{.Names}}' | grep -qx "seceoknight-mongodb"; then
        if docker exec seceoknight-mongodb mongodump \
            --username "${MONGODB_USER:-admin}" --password "${MONGODB_PASSWORD:-}" \
            --authenticationDatabase admin --db "${MONGODB_DB:-seceoknight}" \
            --archive > "${BACKUP_DIR}/mongodb.archive" 2>/dev/null; then
            say "  mongodb.archive written ($(du -h "${BACKUP_DIR}/mongodb.archive" | cut -f1))"
        else
            c_yellow "  [!] mongodump failed — mongodb NOT backed up"
            rm -f "${BACKUP_DIR}/mongodb.archive"
        fi
    else
        c_yellow "  [!] seceoknight-mongodb container not running — skipped"
    fi

    if [ -z "$(ls -A "$BACKUP_DIR" 2>/dev/null)" ]; then
        c_yellow "  [!] Backup directory is empty — nothing was actually saved."
        rmdir "$BACKUP_DIR" 2>/dev/null || true
    else
        chmod 600 "${BACKUP_DIR}"/* 2>/dev/null || true
        c_green "  Backup complete: ${BACKUP_DIR}"
    fi
    echo
fi

# Bring the stack down.
DOWN_ARGS=""
[ "$PURGE" -eq 1 ] && DOWN_ARGS="--volumes"
if [ -n "$COMPOSE_PATH" ]; then
    say "Stopping and removing containers${DOWN_ARGS:+ + volumes} ..."
    docker compose -f "$COMPOSE_PATH" down $DOWN_ARGS --remove-orphans || true
else
    # No compose file: remove by the project's container/volume name prefix.
    say "Removing containers by name ..."
    docker ps -aq --filter "name=seceoknight" | xargs -r docker rm -f || true
    if [ "$PURGE" -eq 1 ]; then
        say "Removing volumes by name ..."
        docker volume ls -q | grep -iE 'seceoknight' | xargs -r docker volume rm || true
    fi
fi

# Purge also removes leftover named volumes the compose down might miss, the
# network, and the install directory.
if [ "$PURGE" -eq 1 ]; then
    say "Removing any remaining SeceoKnight DLP volumes ..."
    docker volume ls -q | grep -iE 'seceoknight' | xargs -r docker volume rm || true
    docker network ls -q --filter "name=seceoknight" | xargs -r docker network rm 2>/dev/null || true
    if [ -d "$INSTALL_DIR" ]; then
        say "Deleting ${INSTALL_DIR} ..."
        rm -rf "$INSTALL_DIR"
    fi
fi

echo
if [ "$PURGE" -eq 1 ]; then
    c_green "SeceoKnight DLP fully removed — containers, data volumes and ${INSTALL_DIR} deleted."
    [ "$BACKUP" -eq 1 ] && say "Any successful DB dumps remain at: /var/backups/seceoknight/"
else
    c_green "SeceoKnight DLP stopped and removed. Data volumes were KEPT."
    say "Reinstall over the existing data:  curl -fsSL https://raw.githubusercontent.com/Seceo-Knight/Seceoknight-DLP/main/install.sh | sudo bash"
    say "Delete the data later:             sudo bash uninstall.sh --purge"
fi
echo
