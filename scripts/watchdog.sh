#!/data/data/com.termux/files/usr/bin/sh
# wifi-zero watchdog: monitor + server se reinician si se caen.
# Lánzalo una vez (p.ej. desde termux-job-scheduler) y cada ciclo comprueba.
set -u
cd "$(dirname "$0")/.."
BD="$(pwd)"
DAT="data/wifi.db"

need_restart() { # $1 = pidfile  $2 = nombre
  if [ -f "$1" ] && kill -0 "$(cat "$1" 2>/dev/null)" 2>/dev/null; then
    return 1
  fi
  return 0
}

# --- monitor
if need_restart logs/monitor.pid monitor; then
  nohup python3 core/monitor.py >> logs/monitor.log 2>&1 &
  echo $! > logs/monitor.pid
  echo "[watchdog] monitor reiniciado ($(cat logs/monitor.pid))"
fi

# --- server web
if need_restart logs/server.pid server; then
  nohup python3 core/server.py >> logs/server.log 2>&1 &
  echo $! > logs/server.pid
  echo "[watchdog] server reiniciado ($(cat logs/server.pid))"
fi

# --- backup si pasaron 24h desde el último
LAST="logs/.backup_last"
if [ ! -f "$LAST" ] || [ $(( $(date +%s) - $(cat "$LAST") )) -ge 86400 ]; then
  mkdir -p data/backups
  cp data/wifi.db "data/backups/wifi-$(date +%Y%m%d-%H%M).db"
  find data/backups -name 'wifi-*.db' -mtime +7 -delete
  date +%s > "$LAST"
  echo "[watchdog] backup diario hecho"
fi
echo "[watchdog] ciclo OK"