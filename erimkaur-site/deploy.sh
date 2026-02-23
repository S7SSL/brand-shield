#!/bin/bash
# Deploy script for erimkaur.com on VPS
# Run as root on 185.249.73.246

set -e

echo "=== Deploying erimkaur.com ==="

# Create web directory
mkdir -p /var/www/erimkaur

# Download landing page from GitHub
curl -sL "https://raw.githubusercontent.com/S7SSL/brand-shield/main/erimkaur-site/index.html" -o /var/www/erimkaur/index.html
echo "[OK] Landing page downloaded"

# Download nginx config
curl -sL "https://raw.githubusercontent.com/S7SSL/brand-shield/main/erimkaur-site/nginx-erimkaur.conf" -o /etc/nginx/sites-available/erimkaur
echo "[OK] Nginx config downloaded"

# Enable site
ln -sf /etc/nginx/sites-available/erimkaur /etc/nginx/sites-enabled/erimkaur

# Remove default if exists
rm -f /etc/nginx/sites-enabled/default

# Test nginx config
nginx -t

# Reload nginx
systemctl reload nginx
echo "[OK] Nginx reloaded"

echo ""
echo "=== DONE ==="
echo "Landing page: http://erimkaur.com"
echo "Brand Shield: http://erimkaur.com/shield/"
echo ""
echo "Next: Set up SSL with certbot"
echo "  apt install certbot python3-certbot-nginx -y"
echo "  certbot --nginx -d erimkaur.com -d www.erimkaur.com"
