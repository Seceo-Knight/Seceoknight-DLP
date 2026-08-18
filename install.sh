#!/usr/bin/env bash
#
# SeceoKnight DLP — Server one-liner installer.
#
# This script downloads ONLY the production docker-compose file and
# environment template — no source code is ever placed on the production
# server. All services run from pre-built images on GHCR.
#
# Usage (one-liner):
#   curl -fsSL https://raw.githubusercontent.com/Seceo-Knight/Seceoknight-DLP/main/install.sh | sudo bash
#
# Or to a custom directory:
#   curl -fsSL https://raw.githubusercontent.com/Seceo-Knight/Seceoknight-DLP/main/install.sh | sudo INSTALL_DIR=/srv/seceoknight bash
#
set -euo pipefail

# ─── Configuration ────────────────────────────────────────────────────
GITHUB_REPO="Seceo-Knight/Seceoknight-DLP"
GITHUB_BRANCH="${GITHUB_BRANCH:-main}"
RAW_BASE="https://raw.githubusercontent.com/${GITHUB_REPO}/${GITHUB_BRANCH}"
INSTALL_DIR="${INSTALL_DIR:-/opt/seceoknight}"
COMPOSE_FILE="docker-compose.prod.yml"
ENV_FILE=".env"
ENV_EXAMPLE=".env.example"

# ─── Helpers ──────────────────────────────────────────────────────────
c_blue()   { printf "\033[1;34m%s\033[0m\n" "$*"; }
c_green()  { printf "\033[1;32m%s\033[0m\n" "$*"; }
c_yellow() { printf "\033[1;33m%s\033[0m\n" "$*"; }
c_red()    { printf "\033[1;31m%s\033[0m\n" "$*" >&2; }
say()      { printf "[+] %s\n" "$*"; }
die()      { c_red "[FATAL] $*"; exit 1; }

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        die "This installer must be run as root (sudo)."
    fi
}

# ─── Banner ───────────────────────────────────────────────────────────
clear || true
c_blue "================================================================"
c_blue "  SeceoKnight DLP — Production Server Installer"
c_blue "================================================================"
echo
say "Repository : ${GITHUB_REPO} (branch ${GITHUB_BRANCH})"
say "Install dir: ${INSTALL_DIR}"
say "No source code will be deployed — only the compose file and .env."
echo

require_root

# ─── 1. Install Docker if missing ─────────────────────────────────────
install_docker() {
    say "Docker not found — installing via official convenience script."
    curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
    sh /tmp/get-docker.sh
    rm -f /tmp/get-docker.sh
    systemctl enable docker
    systemctl start docker
}

if ! command -v docker >/dev/null 2>&1; then
    install_docker
fi

if ! docker compose version >/dev/null 2>&1; then
    die "Docker is installed but 'docker compose' v2 is not available. Upgrade Docker."
fi
say "Docker $(docker --version | awk '{print $3}' | tr -d ',') OK"

# ─── 2. Create install dir ────────────────────────────────────────────
mkdir -p "${INSTALL_DIR}"
cd "${INSTALL_DIR}"
say "Working in ${INSTALL_DIR}"

# ─── 3. Download compose + env template + nginx config ────────────────
say "Downloading ${COMPOSE_FILE}"
curl -fsSL "${RAW_BASE}/${COMPOSE_FILE}" -o "${COMPOSE_FILE}"

if [ ! -f "${ENV_FILE}" ]; then
    say "Downloading ${ENV_EXAMPLE}"
    curl -fsSL "${RAW_BASE}/${ENV_EXAMPLE}" -o "${ENV_EXAMPLE}"
fi

say "Downloading nginx/nginx.conf"
mkdir -p "${INSTALL_DIR}/nginx"
curl -fsSL "${RAW_BASE}/nginx/nginx.conf" -o "${INSTALL_DIR}/nginx/nginx.conf"

# update.sh is the correct way to roll a running install forward -- unlike a
# bare `docker compose pull && up -d`, it also recreates nginx (so it can
# never keep proxying to a stale container IP after manager/dashboard get
# recreated) and re-syncs this compose file + nginx.conf themselves (which
# `pull` never touches, since that only refreshes images). Drop it in now so
# it's already on disk the first time this box needs an update.
say "Downloading update.sh"
curl -fsSL "${RAW_BASE}/update.sh" -o "${INSTALL_DIR}/update.sh"
chmod +x "${INSTALL_DIR}/update.sh"

# ─── 4. Generate .env with secure random secrets ──────────────────────
gen_secret() {
    # 48 chars of url-safe random
    local n="${1:-48}"
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 "$n" | tr -d '/+=' | head -c "$n"
    else
        head -c "$((n*2))" /dev/urandom | tr -dc 'A-Za-z0-9' | head -c "$n"
    fi
}

if [ ! -f "${ENV_FILE}" ]; then
    say "Generating ${ENV_FILE} with secure random passwords"
    cp "${ENV_EXAMPLE}" "${ENV_FILE}"
    SECRET_KEY="$(gen_secret 48)"
    JWT_SECRET="$(gen_secret 48)"
    ENCRYPTION_KEY="$(gen_secret 48)"
    POSTGRES_PASSWORD="$(gen_secret 24)"
    MONGODB_PASSWORD="$(gen_secret 24)"
    REDIS_PASSWORD="$(gen_secret 24)"
    OPENSEARCH_PASSWORD="$(gen_secret 24)"

    # Derive a reasonable default origin from the host's first IP so the
    # API's CORS allowlist is not left wide open and does not need to be
    # hand-edited on every install. Operators can tighten it later.
    HOST_IP_GUESS="$(hostname -I 2>/dev/null | awk '{print $1}' || echo 127.0.0.1)"
    CORS_JSON_DEFAULT="[\"http://${HOST_IP_GUESS}\",\"https://${HOST_IP_GUESS}\",\"http://localhost\",\"http://127.0.0.1\"]"
    ALLOWED_HOSTS_DEFAULT="${HOST_IP_GUESS},localhost,127.0.0.1"

    # Safe in-place substitution. `|` as the sed delimiter so the JSON
    # bracket/quote characters don't need extra escaping.
    sed -i \
        -e "s|change-this-to-a-random-secret-key-min-32-chars|${SECRET_KEY}|" \
        -e "s|change-this-to-a-random-jwt-secret-min-32-chars|${JWT_SECRET}|" \
        -e "s|change-this-to-a-random-encryption-key|${ENCRYPTION_KEY}|" \
        -e "s|change-this-strong-postgres-password|${POSTGRES_PASSWORD}|" \
        -e "s|change-this-strong-mongodb-password|${MONGODB_PASSWORD}|" \
        -e "s|change-this-strong-redis-password|${REDIS_PASSWORD}|" \
        -e "s|change-this-strong-opensearch-password|${OPENSEARCH_PASSWORD}|" \
        -e "s|^CORS_ORIGINS=.*|CORS_ORIGINS=${CORS_JSON_DEFAULT}|" \
        -e "s|^ALLOWED_HOSTS=.*|ALLOWED_HOSTS=${ALLOWED_HOSTS_DEFAULT}|" \
        "${ENV_FILE}"

    chown root:root "${ENV_FILE}"
    chmod 600 "${ENV_FILE}"
    say "${ENV_FILE} created with mode 600 (root only)"
else
    say "${ENV_FILE} already exists — keeping existing secrets"
fi

# ─── 5. Generate self-signed TLS certs if missing ─────────────────────
# docker-compose.prod.yml mounts ./certs/fullchain.pem and ./certs/privkey.pem
# into the dashboard nginx container. The compose-up will fail if those
# files don't exist, so we drop a self-signed pair if the operator hasn't
# provided real certs.
mkdir -p "${INSTALL_DIR}/certs"
chmod 700 "${INSTALL_DIR}/certs"
if [ ! -f "${INSTALL_DIR}/certs/fullchain.pem" ] || [ ! -f "${INSTALL_DIR}/certs/privkey.pem" ]; then
    say "Generating self-signed TLS certificate (replace with real cert later)"
    if command -v openssl >/dev/null 2>&1; then
        # Stronger key (RSA 4096), explicit SAN entries so modern
        # browsers don't reject the cert outright, and the operator's
        # hostname baked in if we can resolve it.
        HOSTNAME_CN="$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo seceoknight.local)"
        HOST_IP_SAN="$(hostname -I 2>/dev/null | awk '{print $1}' || echo 127.0.0.1)"
        openssl req -x509 -nodes -newkey rsa:4096 -days 825 \
            -keyout "${INSTALL_DIR}/certs/privkey.pem" \
            -out    "${INSTALL_DIR}/certs/fullchain.pem" \
            -subj "/CN=${HOSTNAME_CN}/O=SeceoKnight DLP/OU=self-signed" \
            -addext "subjectAltName=DNS:${HOSTNAME_CN},DNS:seceoknight.local,DNS:localhost,IP:127.0.0.1,IP:${HOST_IP_SAN}" \
            -addext "keyUsage=digitalSignature,keyEncipherment" \
            -addext "extendedKeyUsage=serverAuth" \
            >/dev/null 2>&1
        chown root:root "${INSTALL_DIR}/certs/privkey.pem" "${INSTALL_DIR}/certs/fullchain.pem"
        chmod 600 "${INSTALL_DIR}/certs/privkey.pem"
        chmod 644 "${INSTALL_DIR}/certs/fullchain.pem"
    else
        # No openssl — drop empty placeholders just so the bind-mount succeeds.
        : > "${INSTALL_DIR}/certs/fullchain.pem"
        : > "${INSTALL_DIR}/certs/privkey.pem"
        c_yellow "[!] openssl missing — created empty cert placeholders. HTTPS will not work."
    fi
fi

# ─── 6. Create data directories used by bind mounts ───────────────────
# (compose maps quarantine + logs into named volumes by default; this is
# just for any host paths the operator may add later)
mkdir -p "${INSTALL_DIR}/data"

# ─── 7. Pull pre-built images and start ───────────────────────────────
say "Pulling pre-built images from ghcr.io/${GITHUB_REPO} ..."
docker compose -f "${COMPOSE_FILE}" pull

say "Starting all services in detached mode"
docker compose -f "${COMPOSE_FILE}" up -d

# ─── 8. Wait for health ───────────────────────────────────────────────
# Health is checked via nginx (port 443) since manager port 55000 is
# internal-only and not published to the host.
say "Waiting for the API to come up via nginx (max ~3 minutes)"
for i in $(seq 1 90); do
    if curl -fsSk https://localhost/api/v1/health >/dev/null 2>&1; then
        break
    fi
    sleep 2
    printf "."
done
echo

if ! curl -fsSk https://localhost/api/v1/health >/dev/null 2>&1; then
    c_red "[FATAL] API did not become healthy within 3 minutes."
    c_red "Check the logs:"
    c_red "  docker compose -f ${INSTALL_DIR}/${COMPOSE_FILE} logs manager"
    exit 1
fi

# ─── 8b. Mark the migration state ─────────────────────────────────────
# The manager auto-creates the whole schema at startup (Base.metadata.create_all
# in server/app/main.py), so on a fresh install `alembic upgrade head` would
# fail (e.g. "relation already exists") — the tables are already there, they
# just were never recorded as being at a specific Alembic revision. We stamp
# instead, which records the DB as being at the latest revision without
# re-running any migration SQL, so future updates can apply cleanly.
#
# Only stamp when the DB has never been stamped. If this is a re-run against
# an existing install, stamping would silently mark any pending migrations as
# done and skip them — that case is a real upgrade and must use
# `alembic upgrade head` instead. `alembic current` prints the revision on
# stdout when stamped and nothing when it isn't, so non-empty stdout is the
# signal — don't try to detect this any other way.
if [ -n "$(docker exec seceoknight-manager alembic current 2>/dev/null | tr -d '[:space:]')" ]; then
    say "Alembic revision already stamped — leaving migration state untouched"
    c_yellow "  (upgrading an existing install? run: docker exec seceoknight-manager alembic upgrade head)"
else
    say "Stamping database at the latest Alembic revision (fresh install)"
    docker exec seceoknight-manager alembic stamp head >/dev/null 2>&1 \
        && say "Migration state stamped" \
        || c_yellow "[!] Could not stamp Alembic revision — run it manually: docker exec seceoknight-manager alembic stamp head"
fi

# ─── 8c. Package + publish the browser extension (force-install) ──────
# Gap-scan of CyberSentinel-DLP (August 18, 2026): the DLP browser extension
# is force-installed to endpoints via Chrome/Edge enterprise policy
# (ExtensionInstallForcelist), which needs a signed, stable-id package the
# server serves at /api/v1/extension/*. scripts/pack-extension.py builds
# that, but it needs the extension's small source tree (agents/browser-
# extension/, 5 files) on disk to zip -- which this installer otherwise
# never does (see the top of this file: "no source code is ever placed on
# the production server"). So it's fetched into a TEMP directory here and
# deleted immediately after packaging, not left on disk -- the only thing
# that persists is the packaged output (server/extension_dist/, served by
# the running container) and the signing key
# (/etc/seceoknightdlp/extension-signing.pem, which IS meant to persist --
# it's the extension's permanent identity, back it up).
#
# Entirely best-effort / non-fatal: a server that never gets an extension
# packaged just doesn't force-install one, same as any other deployment
# that doesn't use this feature -- it must never abort the rest of the install.
say "Packaging the browser extension for force-install"

if ! python3 -m pip --version >/dev/null 2>&1; then
    say "Installing python3-pip (needed to package the browser extension)"
    apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq python3-pip >/dev/null 2>&1 \
        || c_yellow "[!] Could not install python3-pip -- skipping extension packaging (non-fatal)"
fi

if python3 -m pip --version >/dev/null 2>&1; then
    python3 -m pip show cryptography >/dev/null 2>&1 || {
        say "Installing the 'cryptography' package"
        python3 -m pip install --quiet cryptography --break-system-packages >/dev/null 2>&1 \
            || python3 -m pip install --quiet cryptography >/dev/null 2>&1 \
            || c_yellow "[!] Could not install 'cryptography' -- skipping extension packaging (non-fatal)"
    }
fi

if command -v git >/dev/null 2>&1 && python3 -m pip show cryptography >/dev/null 2>&1; then
    EXT_TMP="$(mktemp -d)"
    # Cleaned up on exit no matter how the script ends -- this directory
    # must never be what's left behind on the server.
    trap 'rm -rf "${EXT_TMP}"' EXIT

    if git clone --quiet --depth 1 "https://github.com/${GITHUB_REPO}.git" "${EXT_TMP}/repo" 2>/dev/null \
        && [ -f "${EXT_TMP}/repo/scripts/pack-extension.py" ]; then
        HOST_IP_FOR_EXT="$(hostname -I 2>/dev/null | awk '{print $1}' || echo localhost)"
        if python3 "${EXT_TMP}/repo/scripts/pack-extension.py" \
            --out "${INSTALL_DIR}/server/extension_dist" \
            --server "http://${HOST_IP_FOR_EXT}" ; then
            say "Browser extension packaged and published -- endpoints force-install it automatically"
        else
            c_yellow "[!] Extension packaging failed (non-fatal) -- run it manually later:"
            c_yellow "    git clone https://github.com/${GITHUB_REPO}.git && cd Seceoknight-DLP"
            c_yellow "    python3 scripts/pack-extension.py --out ${INSTALL_DIR}/server/extension_dist --server http://<this-server>"
        fi
    else
        c_yellow "[!] Could not fetch the extension source -- skipping (non-fatal, same manual command as above)"
    fi

    rm -rf "${EXT_TMP}"
    trap - EXIT
else
    c_yellow "[!] git or 'cryptography' unavailable -- skipping extension packaging (non-fatal)"
    c_yellow "    Install them and run manually later:"
    c_yellow "    git clone https://github.com/${GITHUB_REPO}.git && cd Seceoknight-DLP"
    c_yellow "    python3 scripts/pack-extension.py --out ${INSTALL_DIR}/server/extension_dist --server http://<this-server>"
fi

# ─── 9. Print connection details ──────────────────────────────────────
HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || echo localhost)"

# Admin bootstrap password is NOT fixed — the server generates a random
# CSPRNG password per deployment (server/app/main.py::_generate_admin_password)
# unless DLP_ADMIN_PASSWORD is pinned in .env, and logs it exactly once on
# first boot. Figure out which case we're in so the banner below is accurate
# instead of printing a password that no longer works.
ADMIN_PASS=""
ADMIN_PASS_SOURCE=""

# Case 1: operator pinned it in .env — read that value directly.
PINNED_ADMIN_PASS="$(grep -E '^DLP_ADMIN_PASSWORD=' "${ENV_FILE}" 2>/dev/null | head -1 | cut -d= -f2-)"
if [ -n "${PINNED_ADMIN_PASS}" ]; then
    ADMIN_PASS="${PINNED_ADMIN_PASS}"
    ADMIN_PASS_SOURCE="pinned via DLP_ADMIN_PASSWORD in ${ENV_FILE}"
else
    # Case 2: server auto-generated it — pull it back out of the manager's
    # first-boot log line (logged exactly once, only on a brand-new DB).
    GENERATED_ADMIN_PASS="$(docker compose -f "${COMPOSE_FILE}" logs manager 2>/dev/null \
        | grep -oE '"generated_password"[[:space:]]*:[[:space:]]*"[^"]+"' \
        | head -1 | sed -E 's/.*"generated_password"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')"
    if [ -n "${GENERATED_ADMIN_PASS}" ]; then
        ADMIN_PASS="${GENERATED_ADMIN_PASS}"
        ADMIN_PASS_SOURCE="auto-generated on first boot"
    fi
fi

echo
c_green "================================================================"
c_green "  Installation Complete"
c_green "================================================================"
echo
say "Install dir : ${INSTALL_DIR}"
say "Compose file: ${INSTALL_DIR}/${COMPOSE_FILE}"
say "Env file    : ${INSTALL_DIR}/${ENV_FILE} (mode 600)"
say "Certs       : ${INSTALL_DIR}/certs/  (self-signed unless replaced)"
echo
c_blue "Endpoints (all traffic through Nginx on ports 80/443):"
echo "  Dashboard (HTTP)  : http://${HOST_IP}        (redirects to HTTPS)"
echo "  Dashboard (HTTPS) : https://${HOST_IP}"
echo "  API Docs          : https://${HOST_IP}/api/v1/docs"
echo "  Health probe      : http://localhost:55000/health  (internal only)"
echo
c_yellow "  NOTE: A self-signed TLS certificate was generated automatically."
c_yellow "        Your browser will show a security warning — click 'Advanced'"
c_yellow "        and 'Proceed' to continue. This is normal for self-signed certs."
c_yellow "        For a trusted certificate, run:"
c_yellow "        bash ${INSTALL_DIR}/scripts/generate-certs.sh --domain yourdomain.com --email you@email.com"
echo
c_blue "First-login credentials:"
echo "  Username : admin"
if [ -n "${ADMIN_PASS}" ]; then
    echo "  Password : ${ADMIN_PASS}  (${ADMIN_PASS_SOURCE})"
    c_yellow "  → Change this password after first login (Settings → Profile → Change Password)."
else
    c_yellow "  Password : could not be read automatically (this only happens on a re-run"
    c_yellow "             against an existing database, where no first-boot line was logged)."
    c_yellow "             Retrieve it with:"
    c_yellow "             docker compose -f ${INSTALL_DIR}/${COMPOSE_FILE} logs manager | grep generated_password"
fi
echo
c_blue "Database tier (internal-only — no host port binding):"
echo "  postgres / mongodb / redis / opensearch are reachable only on the"
echo "  internal docker network. Use 'docker compose exec <svc>' for ops."
echo
c_blue "Useful commands:"
echo "  docker compose -f ${INSTALL_DIR}/${COMPOSE_FILE} ps"
echo "  docker compose -f ${INSTALL_DIR}/${COMPOSE_FILE} logs -f manager"
echo "  docker compose -f ${INSTALL_DIR}/${COMPOSE_FILE} down       # stop everything"
echo
c_blue "To update to the latest version:"
echo "  cd ${INSTALL_DIR} && sudo bash update.sh"
c_yellow "  (NOT a bare 'docker compose pull && up -d' -- that leaves nginx pointed"
c_yellow "   at the old container IPs after manager/dashboard are recreated, which"
c_yellow "   surfaces as random-looking 502s or failed logins. update.sh recreates"
c_yellow "   nginx too, re-syncs config files pull alone never touches, and runs"
c_yellow "   any new database migrations.)"
echo
c_blue "Next: install agents on endpoints (run on Windows boxes):"
echo "  powershell -ExecutionPolicy Bypass -Command \"irm ${RAW_BASE}/install-agent.ps1 | iex\""
echo
