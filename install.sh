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
say "Waiting for the manager API to come up (max ~3 minutes)"
for i in $(seq 1 90); do
    if curl -fsS http://localhost:55000/health >/dev/null 2>&1; then
        break
    fi
    sleep 2
    printf "."
done
echo

if ! curl -fsS http://localhost:55000/health >/dev/null 2>&1; then
    c_red "[FATAL] Manager API did not become healthy within 3 minutes."
    c_red "Check the logs:"
    c_red "  docker compose -f ${INSTALL_DIR}/${COMPOSE_FILE} logs manager"
    exit 1
fi

# ─── 9. Print connection details ──────────────────────────────────────
HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || echo localhost)"

# Admin bootstrap password is fixed: Admin@1234.
# Operators are expected to change it after first login via
# Settings -> Profile -> Change Password.
ADMIN_PASS="Admin@1234"

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
echo "  Password : ${ADMIN_PASS}"
c_yellow "  → Change this password after first login (Settings → Profile → Change Password)."
echo
c_blue "Database tier (internal-only — no host port binding):"
echo "  postgres / mongodb / redis / opensearch are reachable only on the"
echo "  internal docker network. Use 'docker compose exec <svc>' for ops."
echo
c_blue "Useful commands:"
echo "  docker compose -f ${INSTALL_DIR}/${COMPOSE_FILE} ps"
echo "  docker compose -f ${INSTALL_DIR}/${COMPOSE_FILE} logs -f manager"
echo "  docker compose -f ${INSTALL_DIR}/${COMPOSE_FILE} pull && \\"
echo "    docker compose -f ${INSTALL_DIR}/${COMPOSE_FILE} up -d   # rolling update"
echo "  docker compose -f ${INSTALL_DIR}/${COMPOSE_FILE} down       # stop everything"
echo
c_blue "Next: install agents on endpoints (run on Windows boxes):"
echo "  powershell -ExecutionPolicy Bypass -Command \"irm ${RAW_BASE}/install-agent.ps1 | iex\""
echo
