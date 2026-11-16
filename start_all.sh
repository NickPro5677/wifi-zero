#!/data/data/com.termux/files/usr/bin/sh
# wifi-zero v4 launcher: supervisor único (panel + monitor)
# La terminal solo sirve para este arranque; el resto se opera desde la PWA.
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
nohup python3 -m core >> logs/server.log 2>&1 &
echo $! > logs/supervisor.pid
log "supervisor pid $(cat logs/supervisor.pid)  http://127.0.0.1:8788"

# espera panel y lanza un scan inicial (localhost, sin token)
sleep 2
for i in 1 2 3 4 5; do
  if curl -s -m 3 -X POST http://127.0.0.1:8788/api/scan >/dev/null 2>&1; then
    log "escaneo inicial lanzado"
    break
  fi
  sleep 2
done
log "listo — abre el panel / instala la PWA; no hace falta más terminal"
