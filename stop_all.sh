#!/data/data/com.termux/files/usr/bin/sh
# wifi-zero stopper
cd "$(dirname "$0")"
for f in logs/monitor.pid logs/server.pid; do
  if [ -f "$f" ]; then
    kill "$(cat "$f")" 2>/dev/null && echo "stopped $(basename "$f")"
    rm -f "$f"
  fi
done
pkill -f "core/server.py" 2>/dev/null || true
pkill -f "core/monitor.py" 2>/dev/null || true
echo "[wifi-zero] detenido"