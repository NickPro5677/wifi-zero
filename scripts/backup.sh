#!/data/data/com.termux/files/usr/bin/sh
# wifi-zero backup manual -> data/backups/wifi-<ts>.db (retiene 7 días).
# Legado CLI — preferible: panel → Sistema → Backup, o POST /api/backup
cd "$(dirname "$0")/.."
mkdir -p data/backups
DEST="data/backups/wifi-$(date +%Y%m%d-%H%M).db"
cp data/wifi.db "$DEST"
find data/backups -name 'wifi-*.db' -mtime +7 -delete
echo "backup: $DEST"
ls -th data/backups/ | head -5