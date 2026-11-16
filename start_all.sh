#!/usr/bin/env sh
# wifi-zero launcher: supervisor único (panel + monitor)
# Primario: Linux/Pi. Termux sigue funcionando si usas este script allí.
# La terminal solo sirve para este arranque; el día a día es la PWA.
set -e

cd "$(dirname "$0")"
BD="$(pwd)"
log() { echo "[wifi-zero] $*"; }

# kill previous if any
[ -f logs/supervisor.pid ] && kill "$(cat logs/supervisor.pid)" 2>/dev/null || true
[ -f logs/monitor.pid ] && kill "$(cat logs/monitor.pid)" 2>/dev/null || true
[ -f logs/server.pid ] && kill "$(cat logs/server.pid)" 2>/dev/null || true
pkill -f "python3 -m core" 2>/dev/null || true
pkill -f "core/server.py" 2>/dev/null || true
pkill -f "core/monitor.py" 2>/dev/null || true
sleep 1

mkdir -p logs data
# Prefer a persisted secret if present and not already exported
if [ -z "${WZ_SESSION_SECRET:-}" ] && [ -f "$HOME/.wifi-zero/session_secret" ]; then
  WZ_SESSION_SECRET="$(cat "$HOME/.wifi-zero/session_secret")"
  export WZ_SESSION_SECRET
fi

nohup python3 -m core >> logs/server.log 2>&1 &
echo $! > logs/supervisor.pid
log "supervisor pid $(cat logs/supervisor.pid)"
log "panel: http://127.0.0.1:8788  (en Pi + PWA usa la IP LAN tras /setup con bind 0.0.0.0)"

# espera panel y lanza un scan inicial (localhost, sin token)
sleep 2
for i in 1 2 3 4 5; do
  if curl -s -m 3 -X POST http://127.0.0.1:8788/api/scan >/dev/null 2>&1; then
    log "escaneo inicial lanzado"
    break
  fi
  sleep 2
done
log "listo — abre el panel desde el teléfono e instala la PWA"
