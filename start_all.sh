#!/data/data/com.termux/files/usr/bin/sh
# wifi-zero launcher: monitor + web panel
set -e

cd "$(dirname "$0")"
BD="$(pwd)"
log() { echo "[wifi-zero] $*"; }

# kill previous if any
[ -f logs/monitor.pid ] && kill "$(cat logs/monitor.pid)" 2>/dev/null || true
[ -f logs/server.pid ] && kill "$(cat logs/server.pid)" 2>/dev/null || true
sleep 1

nohup python3 core/monitor.py >> logs/monitor.log 2>&1 &
echo $! > logs/monitor.pid
log "monitor pid $(cat logs/monitor.pid)"

nohup python3 core/server.py >> logs/server.log 2>&1 &
echo $! > logs/server.pid
log "server pid $(cat logs/server.pid)  http://0.0.0.0:8788"

# me llaman la API una vez para poblar al instante
sleep 2
for i in 1 2; do
  if curl -s -m 3 -X POST http://127.0.0.1:8788/api/scan >/dev/null 2>&1; then
    log "escaneo inicial lanzado"
    break
  fi
  sleep 2
done
log "listo"