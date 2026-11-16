#!/data/data/com.termux/files/usr/bin/sh
# wifi-zero healthcheck (legado CLI — preferible: panel → Sistema → checks
# o POST /api/checks)
set -u
cd "$(dirname "$0")"
fail=0
ck() { # name, ok/message
  if [ "${2:-}" = "ok" ]; then echo "  [ok]   $1"; else echo "  [FAIL] $1 — ${3:-sin detalles}"; fail=1; fi
}

echo "== wifi-zero checks =="

ck "interfaz wlan0" "$(/system/bin/ip -brief addr show wlan0 2>/dev/null | grep -q '192\.168\.' && echo ok || echo no)"
ck "ip (system)" "$(test -x /system/bin/ip && echo ok || echo no)"
ck "nmap OUI db" "$(test -f /data/data/com.termux/files/usr/share/nmap/nmap-mac-prefixes && echo ok || echo no)"
ck "termux-wifi-scaninfo" "$(test -x /data/data/com.termux/files/usr/bin/termux-wifi-scaninfo && echo ok || echo no)"

# python modules
python3 - <<'PY' >/dev/null 2>&1 && echo "  [ok]   python + sqlite3" || { echo "  [FAIL] python3/sqlite3"; fail=1; }
import sys, sqlite3; sys.path.insert(0, "."); import core.db
PY

# db exists and has rows
if [ -f data/wifi.db ]; then
  n=$(python3 -c "import sys;sys.path.insert(0,'.');import core.db as d;print(len(d.all_hosts(d.connect())))" 2>/dev/null)
  echo "  [ok]   base de datos ($n hosts)"
else
  echo "  [FAIL] falta data/wifi.db"; fail=1
fi

# server responsiveness
if curl -s -m 4 http://127.0.0.1:8788/api/stats >/dev/null 2>&1; then
  echo "  [ok]   panel web 8788"
else
  echo "  [FAIL] panel web 8788 caído"; fail=1
fi

# monitor running
if test -f logs/monitor.pid && kill -0 "$(cat logs/monitor.pid)" 2>/dev/null; then
  echo "  [ok]   monitor corriendo"
else
  echo "  [FAIL] monitor caído"; fail=1
fi

echo "== resultado: $([ $fail -eq 0 ] && echo TODO OK || echo 'hay fallos') =="
exit $fail