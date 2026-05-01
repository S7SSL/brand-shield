#!/bin/bash
# backup-local.sh — daily local snapshot of the brand-shield SQLite DB.
# Invoked by com.byerim.brand-shield-backup.plist at 03:30 daily.
#
# Why this exists: the live DB is being written to all day. A naive `cp` can
# corrupt the snapshot. Instead we use SQLite's `.backup` command which
# produces a transactionally consistent copy without locking the live DB.
#
# Output:
#   ~/Documents/Claude/brand-shield-backups/brand_shield-YYYY-MM-DD-HHMM.db
#
# Retention: prunes anything older than 90 days.

set -euo pipefail

LIVE_DB="$HOME/Library/Application Support/brand-shield/brand_shield.db"
BACKUP_DIR="$HOME/Documents/Claude/brand-shield-backups"
TIMESTAMP=$(date +%Y-%m-%d-%H%M)
OUT="$BACKUP_DIR/brand_shield-$TIMESTAMP.db"

mkdir -p "$BACKUP_DIR"

if [[ ! -f "$LIVE_DB" ]]; then
  echo "[$(date)] live DB not found at $LIVE_DB — skipping backup"
  exit 0
fi

# Consistent snapshot via SQLite's backup command
sqlite3 "$LIVE_DB" ".backup '$OUT'"

# "latest" symlink for easy reference
ln -sf "$OUT" "$BACKUP_DIR/brand_shield-latest.db"

# Prune backups older than 90 days
find "$BACKUP_DIR" -maxdepth 1 -name 'brand_shield-*.db' -type f -mtime +90 -delete

SIZE=$(du -h "$OUT" | cut -f1)
echo "[$(date)] snapshot saved: $OUT ($SIZE)"
