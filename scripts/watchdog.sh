#!/data/data/com.termux/files/usr/bin/sh
# wifi-zero watchdog v4: reinicia el supervisor único si se cae.
# Lánzalo periódicamente (Termux:Boot, Widget, termux-job-scheduler).
# NO arranca monitor+server por separado — usa `python3 -m core`.
set -u
cd "$(dirname "$0")/.."
mkdir -p logs data

need_restart() { # $1 = pidfile
  if [ -f "$1" ] && kill -0 "$(cat "$1" 2>/dev/null)" 2>/dev/null; then
    return 1
  fi
  return 0
}

# --- supervisor (panel + monitor en un proceso)
if need_restart logs/supervisor.pid; then
  # limpia pidfiles huérfanos de v3
  rm -f logs/monitor.pid logs/server.pid
  nohup python3 -m core >> logs/server.log 2>&1 &
  echo $! > logs/supervisor.pid
  echo "[watchdog] supervisor reiniciado ($(cat logs/supervisor.pid))"
fi

# --- backup diario WAL-safe (API sqlite3 vía core.checks)
LAST="logs/.backup_last"
if [ ! -f "$LAST" ] || [ $(( $(date +%s) - $(cat "$LAST") )) -ge 86400 ]; then
  if python3 -c "from core.checks import make_backup; r=make_backup(); raise SystemExit(0 if r.get('ok') else 1)"; then
    date +%s > "$LAST"
    echo "[watchdog] backup diario hecho"
  else
    echo "[watchdog] backup falló (¿falta data/wifi.db?)"
  fi
fi
echo "[watchdog] ciclo OK"
