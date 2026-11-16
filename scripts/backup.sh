#!/data/data/com.termux/files/usr/bin/sh
# wifi-zero backup WAL-safe → data/backups/wifi-<ts>.db (retiene 7 días).
# Usa la API sqlite3 (core.checks.make_backup), no cp sobre WAL activo.
# Legado CLI — preferible: panel → Sistema → Backup, o POST /api/backup
cd "$(dirname "$0")/.."
python3 - <<'PY'
from core.checks import make_backup
import json
r = make_backup()
print(json.dumps(r, ensure_ascii=False, indent=2))
raise SystemExit(0 if r.get("ok") else 1)
PY
