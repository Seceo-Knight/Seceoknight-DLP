#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# SeceoKnight DLP — SSL Certificate Generator
#
# Usage:
#   Real domain  (Let's Encrypt):  bash scripts/generate-certs.sh --domain dlp.mycompany.com --email admin@mycompany.com
#   IP / local   (self-signed):    bash scripts/generate-certs.sh --self-signed
#
# Output:
#   ./certs/fullchain.pem
#   ./certs/privkey.pem
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

CERTS_DIR="$(cd "$(dirname "$0")/.." && pwd)/certs"
DOMAIN=""
EMAIL=""
SELF_SIGNED=false

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain)       DOMAIN="$2";      shift 2 ;;
        --email)        EMAIL="$2";       shift 2 ;;
        --self-signed)  SELF_SIGNED=true; shift   ;;
        *)
            echo "Unknown option: $1"
            echo "Usage:"
            echo "  $0 --domain <domain> --email <email>   # Let's Encrypt"
            echo "  $0 --self-signed                       # Self-signed (local/IP)"
            exit 1
            ;;
    esac
done

mkdir -p "$CERTS_DIR"

# ── Self-signed certificate ───────────────────────────────────────────────────
if [[ "$SELF_SIGNED" == "true" ]]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Generating self-signed certificate (local / IP use)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if ! command -v openssl &>/dev/null; then
        echo "ERROR: openssl is not installed. Run: sudo apt install openssl"
        exit 1
    fi

    # Get server IP for the SAN field
    SERVER_IP=$(hostname -I | awk '{print $1}')
    echo "Server IP detected: $SERVER_IP"

    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$CERTS_DIR/privkey.pem" \
        -out    "$CERTS_DIR/fullchain.pem" \
        -subj   "/CN=seceoknight-dlp/O=SeceoKnight/C=US" \
        -addext "subjectAltName=IP:${SERVER_IP},IP:127.0.0.1,DNS:localhost"

    echo ""
    echo "✅ Self-signed certificate created:"
    echo "   $CERTS_DIR/fullchain.pem"
    echo "   $CERTS_DIR/privkey.pem"
    echo ""
    echo "⚠️  IMPORTANT: Browsers will show a security warning for self-signed certs."
    echo "   For production with a real domain, run:"
    echo "   $0 --domain <your-domain> --email <your-email>"
    echo ""
    echo "   To bypass the warning in agents/curl, use --insecure or add the cert"
    echo "   to your trusted CA store."
    exit 0
fi

# ── Let's Encrypt certificate ─────────────────────────────────────────────────
if [[ -z "$DOMAIN" || -z "$EMAIL" ]]; then
    echo "ERROR: --domain and --email are required for Let's Encrypt."
    echo "Usage: $0 --domain dlp.mycompany.com --email admin@mycompany.com"
    exit 1
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Requesting Let's Encrypt certificate for: $DOMAIN"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Install certbot if missing
if ! command -v certbot &>/dev/null; then
    echo "certbot not found — installing..."
    sudo apt-get update -qq
    sudo apt-get install -y certbot
fi

# Port 80 must be free for the standalone challenge.
# If Nginx is already running, use webroot instead.
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "seceoknight-nginx"; then
    echo "Nginx is running — using webroot challenge..."
    WEBROOT_PATH="/tmp/certbot-webroot"
    mkdir -p "$WEBROOT_PATH"

    sudo certbot certonly \
        --webroot \
        --webroot-path="$WEBROOT_PATH" \
        --non-interactive \
        --agree-tos \
        --email "$EMAIL" \
        -d "$DOMAIN"
else
    echo "Nginx not running — using standalone challenge (port 80 must be free)..."
    sudo certbot certonly \
        --standalone \
        --non-interactive \
        --agree-tos \
        --email "$EMAIL" \
        -d "$DOMAIN"
fi

# Copy certs to ./certs/ where docker-compose expects them
LETSENCRYPT_DIR="/etc/letsencrypt/live/$DOMAIN"
sudo cp "$LETSENCRYPT_DIR/fullchain.pem" "$CERTS_DIR/fullchain.pem"
sudo cp "$LETSENCRYPT_DIR/privkey.pem"   "$CERTS_DIR/privkey.pem"
sudo chown "$USER:$USER" "$CERTS_DIR/fullchain.pem" "$CERTS_DIR/privkey.pem"
chmod 644 "$CERTS_DIR/fullchain.pem"
chmod 600 "$CERTS_DIR/privkey.pem"

echo ""
echo "✅ Let's Encrypt certificate installed:"
echo "   $CERTS_DIR/fullchain.pem"
echo "   $CERTS_DIR/privkey.pem"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Auto-renewal setup"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Add a cron job to auto-renew and copy certs every 60 days
CRON_CMD="0 3 * * * certbot renew --quiet && cp /etc/letsencrypt/live/$DOMAIN/fullchain.pem $CERTS_DIR/fullchain.pem && cp /etc/letsencrypt/live/$DOMAIN/privkey.pem $CERTS_DIR/privkey.pem && docker exec seceoknight-nginx nginx -s reload"
( crontab -l 2>/dev/null | grep -v "certbot renew"; echo "$CRON_CMD" ) | crontab -
echo "✅ Auto-renewal cron job added (runs at 3am daily, renews when <30 days left)"
echo ""
echo "Next step: Update your .env file:"
echo "   CORS_ORIGINS=[\"https://$DOMAIN\"]"
echo "   ALLOWED_HOSTS=$DOMAIN"
echo ""
echo "Then restart:"
echo "   docker compose -f docker-compose.prod.yml up -d"
