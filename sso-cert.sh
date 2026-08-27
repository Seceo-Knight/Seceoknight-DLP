#!/usr/bin/env bash
#
# SeceoKnight DLP — SIEM SSO trust-anchor setup.
#
# Gap-scan of CyberSentinel-DLP commit c87c966 ("one command to point SSO at
# a SIEM and trust its certificate"), August 25, 2026.
#
# Wiring SIEM SSO by hand means dropping a PEM into ./config/, hand-editing
# SIEM_JWKS_URL/SIEM_JWKS_CA_BUNDLE in .env, knowing `up -d` re-reads the
# environment while `restart` does not, and having no way to check the
# result short of waiting for a real login to fail. This script does all of
# it and then proves it worked by fetching the JWKS from INSIDE the manager
# container, the exact way the manager itself does it (app.core.sso_jwks) --
# a curl from the host proves nothing about either the container's network
# path or the certificate it actually trusts.
#
# Usage (run from the install directory, e.g. /opt/seceoknight):
#   sudo bash sso-cert.sh url <jwks-url>       # set SIEM_JWKS_URL
#   sudo bash sso-cert.sh fetch <host:port>    # take the cert off the SIEM,
#                                               # show its fingerprint, install it
#   sudo bash sso-cert.sh install <file|->     # install one you were handed
#   sudo bash sso-cert.sh check                # prove the manager can verify tokens
#
# An http:// JWKS URL is refused: that document is the trust anchor for
# every RS256 SSO login, so whoever answers for it can mint tokens this
# deployment would accept. Fetching it in cleartext defeats the whole point
# of pinning it. A private key is refused too -- the SIEM's key and its
# certificate get handed over together and the filenames look alike, but
# verifying an identity needs only the public half.
#
# Which certificate to pin: pinning the issuing CA (not the SIEM's own leaf
# certificate) lets the SIEM renew without anyone touching the DLP; pinning
# a self-signed leaf means reinstalling at every renewal, and the fetch
# fails CLOSED -- the morning it expires, every SSO login stops while
# nothing else looks wrong. `check` below prints the expiry and warns
# inside 30 days.
set -euo pipefail

# ─── Configuration ────────────────────────────────────────────────────
INSTALL_DIR="${INSTALL_DIR:-$(pwd)}"
COMPOSE_FILE="docker-compose.prod.yml"
ENVF="${INSTALL_DIR}/.env"
# SeceoKnight already mounts ./config as /etc/seceoknight:ro on the manager
# (docker-compose.prod.yml) -- reuse that existing mount instead of adding a
# new one, unlike CyberSentinel's dedicated ./certs directory.
CONFIG_DIR="${INSTALL_DIR}/config"
CERT_FILE="${CONFIG_DIR}/siem-jwks.pem"
CERT_IN_CONTAINER="/etc/seceoknight/siem-jwks.pem"

# ─── Helpers (same vocabulary as update.sh, for consistency) ───────────
c_blue()   { printf "\033[1;34m%s\033[0m\n" "$*"; }
c_green()  { printf "\033[1;32m%s\033[0m\n" "$*"; }
c_yellow() { printf "\033[1;33m%s\033[0m\n" "$*"; }
c_red()    { printf "\033[1;31m%s\033[0m\n" "$*" >&2; }
say()      { printf "[+] %s\n" "$*"; }
ok()       { c_green "[+] $*"; }
warn()     { c_yellow "[!] $*"; }
err()      { c_red "[x] $*"; }
die()      { c_red "[FATAL] $*"; exit 1; }
kv()       { printf "  %-14s %s\n" "$1" "$2"; }
hd()       { printf "\n"; c_blue "== $* =="; }

if [ "$(id -u)" -ne 0 ]; then
    die "This script must be run as root (sudo) -- it edits .env and recreates the manager container."
fi
if [ ! -f "${INSTALL_DIR}/${COMPOSE_FILE}" ]; then
    die "${INSTALL_DIR}/${COMPOSE_FILE} not found. Run this from your install directory (default /opt/seceoknight), or set INSTALL_DIR=/path/to/install."
fi
cd "${INSTALL_DIR}"

dc() { docker compose -f "${COMPOSE_FILE}" "$@"; }
# load a single key from .env without exposing the whole file
envget() { [ -f "${ENVF}" ] && sed -n "s/^$1=//p" "${ENVF}" | head -1 | tr -d '"'"'"' '; }
# Set KEY=VALUE in .env, replacing an existing line (commented or not) in
# place so its position and surrounding comments survive. Appends when absent.
envset() {
    local k="$1" v="$2"
    [ -f "${ENVF}" ] || touch "${ENVF}"
    if grep -qE "^[#[:space:]]*${k}=" "${ENVF}"; then
        local tmp; tmp="$(mktemp)"
        awk -v k="$k" -v v="$v" '
            !done && $0 ~ "^[#[:space:]]*" k "=" { print k "=" v; done=1; next }
            { print }
        ' "${ENVF}" > "$tmp" && cat "$tmp" > "${ENVF}" && rm -f "$tmp"
    else
        printf '%s=%s\n' "$k" "$v" >> "${ENVF}"
    fi
}

_cert_summary() {
    local f="$1"
    command -v openssl >/dev/null 2>&1 || { warn "openssl not on this host -- cannot summarise the certificate"; return 0; }
    kv "subject" "$(openssl x509 -in "$f" -noout -subject 2>/dev/null | sed 's/^subject=//')"
    kv "issuer"  "$(openssl x509 -in "$f" -noout -issuer  2>/dev/null | sed 's/^issuer=//')"
    kv "names"   "$(openssl x509 -in "$f" -noout -ext subjectAltName 2>/dev/null | tail -n +2 | tr -d ' ' | tr '\n' ' ')"
    local nb na; nb="$(openssl x509 -in "$f" -noout -startdate 2>/dev/null | cut -d= -f2)"
    na="$(openssl x509 -in "$f" -noout -enddate 2>/dev/null | cut -d= -f2)"
    kv "valid"   "$nb  ->  $na"
    # Expiry is the failure nobody schedules. The JWKS fetch fails CLOSED, so
    # the morning this certificate lapses every SSO login stops with a TLS
    # error and nothing else on the dashboard looks wrong.
    if openssl x509 -in "$f" -noout -checkend 0 >/dev/null 2>&1; then
        if ! openssl x509 -in "$f" -noout -checkend 2592000 >/dev/null 2>&1; then
            warn "expires in under 30 days -- SSO logins will stop when it does"
        fi
    else
        err "this certificate has ALREADY EXPIRED -- SSO will not work with it"
    fi
    if openssl x509 -in "$f" -noout -subject -issuer 2>/dev/null | awk -F'=' 'NR==1{s=$0} NR==2{i=$0} END{exit !(substr(s,9)==substr(i,8))}'; then
        kv "type" "self-signed (pins this exact certificate; reinstall on renewal)"
    fi
}

cmd_url() {
    local u="${1:-}"
    [ -n "$u" ] || die "usage: sso-cert.sh url <jwks-url>   (e.g. https://10.200.10.23:3000/api/sso/jwks.json)"
    case "$u" in
        https://*) ;;
        http://*)  die "refusing an http:// JWKS URL -- this document is the trust anchor for every SSO login" ;;
        *)         die "that does not look like a URL" ;;
    esac
    envset SIEM_JWKS_URL "$u"
    ok "SIEM_JWKS_URL=$u in $(basename "${ENVF}")"
    # up -d, not restart: restart reuses the old environment, so the
    # container would come back without ever seeing the new value.
    dc up -d manager >/dev/null 2>&1 && ok "manager recreated with the new environment" \
                                     || err "could not recreate the manager"
    sleep 3
    cmd_check
}

cmd_fetch() {
    local hostport="${1:-}"
    [ -n "$hostport" ] || die "usage: sso-cert.sh fetch <host:port>   (e.g. 10.200.10.23:3000)"
    command -v openssl >/dev/null 2>&1 || die "openssl is required for fetch"
    hd "fetching the certificate presented by $hostport"
    local tmp; tmp="$(mktemp)"
    if ! openssl s_client -connect "$hostport" -servername "${hostport%%:*}" </dev/null 2>/dev/null \
         | openssl x509 -outform pem > "$tmp" 2>/dev/null || [ ! -s "$tmp" ]; then
        rm -f "$tmp"; die "could not retrieve a certificate from $hostport"
    fi
    _cert_summary "$tmp"
    echo
    warn "fetched over an UNVERIFIED connection -- confirm the fingerprint below with"
    warn "whoever runs the SIEM before trusting it:"
    kv "sha256" "$(openssl x509 -in "$tmp" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)"
    echo
    cmd_install "$tmp"
    rm -f "$tmp"
}

cmd_install() {
    local src="${1:-}"
    [ -n "$src" ] || die "usage: sso-cert.sh install <file.pem|->   ('-' reads stdin)"
    local tmp; tmp="$(mktemp)"
    if [ "$src" = "-" ]; then cat > "$tmp"; else cp "$src" "$tmp" 2>/dev/null || { rm -f "$tmp"; die "cannot read $src"; }; fi

    # A trust store holds public certificates and nothing else. Refusing a
    # private key here is not paranoia: the SIEM's key and its certificate
    # are usually handed over together, the file names look alike, and
    # ./config is world-readable inside the container.
    if grep -q "PRIVATE KEY" "$tmp"; then
        rm -f "$tmp"
        err "that file contains a PRIVATE KEY. Only the certificate belongs here."
        die "Send the public certificate instead (the -----BEGIN CERTIFICATE----- block)."
    fi
    if ! grep -q "BEGIN CERTIFICATE" "$tmp"; then
        rm -f "$tmp"; die "no PEM certificate found in that input"
    fi
    if command -v openssl >/dev/null 2>&1 && ! openssl x509 -in "$tmp" -noout >/dev/null 2>&1; then
        rm -f "$tmp"; die "that is not a valid PEM certificate"
    fi

    hd "installing the SIEM JWKS trust anchor"
    _cert_summary "$tmp"
    mkdir -p "${CONFIG_DIR}"
    cat "$tmp" > "${CERT_FILE}"; chmod 0644 "${CERT_FILE}"; rm -f "$tmp"
    ok "written: ${CERT_FILE}"

    envset SIEM_JWKS_CA_BUNDLE "${CERT_IN_CONTAINER}"
    ok "SIEM_JWKS_CA_BUNDLE=${CERT_IN_CONTAINER} in $(basename "${ENVF}")"

    hd "applying to the manager"
    dc up -d manager >/dev/null 2>&1 && ok "manager recreated with the new environment" \
                                     || err "could not recreate the manager"
    sleep 3
    cmd_check
}

cmd_check() {
    hd "SSO trust anchor"
    local url bundle
    url="$(envget SIEM_JWKS_URL)"; bundle="$(envget SIEM_JWKS_CA_BUNDLE)"
    kv "SIEM_JWKS_URL" "${url:-<unset -- SSO falls back to HS256 with DLP_SSO_SECRET>}"
    kv "CA bundle"     "${bundle:-<unset -- the system CA store is used>}"
    [ -f "${CERT_FILE}" ] && _cert_summary "${CERT_FILE}"

    if [ -n "$bundle" ]; then
        # Branch on the ANSWER, not on the exit code. `exec` fails for
        # reasons that have nothing to do with the file -- a stopped
        # manager, or a compose file that cannot be interpolated -- and
        # reporting every one of those as "the certificate is not mounted"
        # sends you to fix a mount that was never broken.
        local seen
        seen="$(dc exec -T manager sh -c "test -f '$bundle' && echo PRESENT || echo MISSING" 2>/dev/null | tr -d '\r' | tail -1)"
        case "$seen" in
            PRESENT) ok "bundle is present inside the manager container" ;;
            MISSING) err "the manager is running but $bundle is not there -- is ./config mounted?"; return 1 ;;
            *)       err "could not ask the manager (is it running? is ${COMPOSE_FILE} the right compose file?)"
                     return 1 ;;
        esac
    fi

    if [ -z "$url" ]; then
        warn "no SIEM_JWKS_URL set, so there is nothing to fetch yet"
        warn "set it with: sso-cert.sh url https://<siem-host>:<port>/api/sso/jwks.json"
        return 0
    fi

    # Verified exactly the way the application does it, from inside the
    # container the application runs in. A curl from the host proves
    # nothing about either.
    echo; hd "fetching the JWKS the way the manager will"
    local out
    # Reports the manager's OWN view of the settings before fetching. .env
    # is what you edited; this is what the running container was started
    # with, and an edit that never reached it is invisible otherwise -- the
    # display shows the new values while the failure comes from the old ones.
    out="$(dc exec -T manager python -c "
import asyncio
from app.core.config import settings
from app.core.sso_jwks import _fetch
print('ENV_URL ' + (settings.SIEM_JWKS_URL or ''))
print('ENV_CA ' + (settings.SIEM_JWKS_CA_BUNDLE or ''))
try:
    ks = asyncio.run(_fetch(settings.SIEM_JWKS_URL))
    print('OK ' + str(len(ks)) + ' key(s): ' + ','.join(
        (k.get('kid') or '?') + '/' + (k.get('alg') or k.get('kty') or '?') for k in ks))
except Exception as e:
    print('FAIL ' + type(e).__name__ + ': ' + str(e)[:300])
" 2>/dev/null | tr -d '\r')"

    local live_url live_ca stale=""
    live_url="$(printf '%s\n' "$out" | sed -n 's/^ENV_URL //p' | head -1)"
    live_ca="$(printf '%s\n' "$out" | sed -n 's/^ENV_CA //p'  | head -1)"
    out="$(printf '%s\n' "$out" | grep -vE '^ENV_(URL|CA) ')"
    if [ -n "$out" ]; then
        [ "$live_url" = "$url" ]    || stale="SIEM_JWKS_URL"
        [ "$live_ca"  = "$bundle" ] || stale="${stale:+$stale and }SIEM_JWKS_CA_BUNDLE"
    fi
    if [ -n "$stale" ]; then
        warn "the manager is running with a DIFFERENT $stale than $(basename "${ENVF}") says"
        kv "  manager has" "${live_url:-<unset>}  |  ${live_ca:-<unset>}"
        warn "it has not been recreated since that edit -- fix with: docker compose -f ${COMPOSE_FILE} up -d manager"
        echo
    fi
    case "$out" in
        OK*)   ok "${out#OK }" ; ok "SSO can verify tokens from this SIEM" ;;
        FAIL*) err "${out#FAIL }"
               echo
               warn "if this is a certificate error, the SIEM is presenting something other"
               warn "than what is installed -- re-run: sudo bash sso-cert.sh fetch <host:port>" ;;
        *)     err "could not run the check inside the manager container"
               [ -n "$out" ] && echo "  $out" ;;
    esac
}

usage() {
    cat <<'EOF'
SeceoKnight DLP -- SIEM SSO trust-anchor setup

  sudo bash sso-cert.sh url <jwks-url>       Point SSO at the SIEM's JWKS endpoint.
  sudo bash sso-cert.sh fetch <host:port>    Retrieve the certificate the SIEM presents,
                                              show its fingerprint, then install it.
                                              Use this on a new server.
  sudo bash sso-cert.sh install <file|->     Install a certificate you were given
                                              (or pipe it in with '-'), set
                                              SIEM_JWKS_CA_BUNDLE, recreate the
                                              manager, and verify.
  sudo bash sso-cert.sh check                Show the SSO trust anchor and fetch the
                                              SIEM's JWKS the way the manager does --
                                              the one check that proves SSO can
                                              verify tokens.

Examples:
  sudo bash sso-cert.sh fetch 10.200.10.23:3000   # trust a self-signed SIEM for SSO
  sudo bash sso-cert.sh check                     # can the manager verify SSO tokens right now?
EOF
}

case "${1:-}" in
    url)     shift; cmd_url "$@";;
    fetch)   shift; cmd_fetch "$@";;
    install) shift; cmd_install "$@";;
    check|show|"") cmd_check;;
    -h|--help|help) usage;;
    *) err "unknown command: $1"; echo; usage; exit 1;;
esac
