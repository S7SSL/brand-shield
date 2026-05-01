#!/bin/bash
# install-mac.sh — set up brand-shield to run on macOS as a launchd service.
#
# What it does:
#   - Verifies Python 3.11+
#   - Creates a venv at ~/code/brand-shield/.venv
#   - Installs requirements
#   - Creates the data directory at ~/Library/Application Support/brand-shield/
#   - Generates a sample .env file (you fill in the secret values)
#   - Installs the launchd plist that runs the app on boot
#
# Run once:    bash scripts/install-mac.sh
# Re-run safely; idempotent.

set -euo pipefail

REPO_DIR="$HOME/code/brand-shield"
VENV_DIR="$REPO_DIR/.venv"
DATA_DIR="$HOME/Library/Application Support/brand-shield"
BACKUP_DIR="$HOME/Documents/Claude/brand-shield-backups"
LOG_DIR="$HOME/Library/Logs"
LAUNCH_AGENTS_DIR="$HOME/Library/LaunchAgents"
APP_PLIST="$LAUNCH_AGENTS_DIR/com.byerim.brand-shield.plist"
BACKUP_PLIST="$LAUNCH_AGENTS_DIR/com.byerim.brand-shield-backup.plist"
ENV_FILE="$REPO_DIR/.env"

echo "→ checking Python"
if ! command -v python3 &>/dev/null; then
  echo "✗ python3 not found. Install via: brew install python@3.11" >&2
  exit 1
fi
PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "  python3 = $PY_VERSION"
if [[ "$(printf '%s\n' "3.11" "$PY_VERSION" | sort -V | head -n1)" != "3.11" ]]; then
  echo "✗ need python 3.11 or newer (found $PY_VERSION). brew install python@3.12" >&2
  exit 1
fi

echo "→ creating venv at $VENV_DIR"
if [[ ! -d "$VENV_DIR" ]]; then
  python3 -m venv "$VENV_DIR"
fi
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
pip install --quiet --upgrade pip
pip install --quiet -r "$REPO_DIR/requirements.txt"
echo "  deps installed"

echo "→ creating data directories"
mkdir -p "$DATA_DIR"
mkdir -p "$BACKUP_DIR"
mkdir -p "$LOG_DIR"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "→ writing sample .env (fill in the secret values)"
  cat > "$ENV_FILE" <<'ENVTEMPLATE'
# Mac Mini deployment env vars for brand-shield.
# This file is gitignored. Fill in the placeholders below before starting.

SECRET_KEY=replace-with-a-long-random-string
BS_DATA_DIR=__DATA_DIR_PLACEHOLDER__

# Search backend (primary)
BRAVE_API_KEY=

# Email — DMCA + weekly report sender
RESEND_API_KEY=
RESEND_FROM=BrandDefend <legal@byerim.com>
LEGAL_BCC=legal@byerim.com
REPORT_RECIPIENTS=sat@byerim.com,erim@byerim.com

# Optional fallback search backend
GOOGLE_CSE_API_KEY=
GOOGLE_CSE_CX=

# Production tweaks
PORT=5050
HOST=127.0.0.1
DEBUG=false
ENVTEMPLATE
  # Substitute the actual data dir
  if command -v gsed &>/dev/null; then
    gsed -i "s|__DATA_DIR_PLACEHOLDER__|$DATA_DIR|" "$ENV_FILE"
  else
    sed -i '' "s|__DATA_DIR_PLACEHOLDER__|$DATA_DIR|" "$ENV_FILE"
  fi
  echo "  wrote $ENV_FILE — edit it and paste your real keys before continuing"
else
  echo "  $ENV_FILE already exists — skipping (delete it manually to regenerate)"
fi

echo "→ installing launchd plists"
mkdir -p "$LAUNCH_AGENTS_DIR"
# Substitute $HOME into the plist templates so they have absolute paths
sed "s|__HOME__|$HOME|g" "$REPO_DIR/scripts/com.byerim.brand-shield.plist" > "$APP_PLIST"
sed "s|__HOME__|$HOME|g" "$REPO_DIR/scripts/com.byerim.brand-shield-backup.plist" > "$BACKUP_PLIST"
echo "  $APP_PLIST"
echo "  $BACKUP_PLIST"

echo
echo "✓ install complete."
echo
echo "Next steps:"
echo "  1. Edit $ENV_FILE and paste your keys (BRAVE_API_KEY, RESEND_API_KEY, SECRET_KEY)"
echo "  2. Load both launchd services:"
echo "       launchctl bootstrap gui/\$(id -u) $APP_PLIST"
echo "       launchctl bootstrap gui/\$(id -u) $BACKUP_PLIST"
echo "  3. Verify the app is running:"
echo "       curl -s http://127.0.0.1:5050/health"
echo "  4. Set up Tailscale (if not already): https://tailscale.com/download/macos"
echo "       Once connected, the app is reachable at http://<this-mac-tailscale-name>:5050"
echo
echo "To stop / restart:"
echo "  launchctl bootout gui/\$(id -u)/com.byerim.brand-shield"
echo "  launchctl bootstrap gui/\$(id -u) $APP_PLIST"
echo
