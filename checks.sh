#!/usr/bin/env sh
# wifi-zero healthcheck (legado CLI — preferible: panel → Sistema → checks
# o POST /api/checks). Portable: Linux/Pi y Termux.
set -u
cd "$(dirname "$0")"
fail=0
ck() { # name, ok/message
  if [ "${2:-}" = "ok" ]; then echo "  [ok]   $1"; else echo "  [FAIL] $1 — ${3:-sin detalles}"; fail=1; fi
}
cko() { # optional check — never fails the run
  if [ "${2:-}" = "ok" ]; then echo "  [ok]   $1"; else echo "  [skip] $1 — ${3:-opcional}"; fi
}

echo "== wifi-zero checks =="

# iproute2
IP_BIN="$(command -v ip 2>/dev/null || true)"
[ -z "$IP_BIN" ] && [ -x /system/bin/ip ] && IP_BIN=/system/bin/ip
if [ -n "$IP_BIN" ]; then
  ck "ip (iproute2)" ok
  if "$IP_BIN" -brief addr 2>/dev/null | grep -Eq '192\.168\.|10\.|172\.'; then
    ck "interfaz LAN" ok
  else
    ck "interfaz LAN" no "sin IPv4 privada"
  fi
else
  ck "ip (iproute2)" no "no encontrado"
  ck "interfaz LAN" no "sin ip"
fi

# OUI (nmap) — Termux o Debian
OUI=""
for p in \
  /usr/share/nmap/nmap-mac-prefixes \
  /usr/local/share/nmap/nmap-mac-prefixes \
  /data/data/com.termux/files/usr/share/nmap/nmap-mac-prefixes
do
  [ -f "$p" ] && OUI="$p" && break
done
if [ -n "$OUI" ]; then ck "nmap OUI db" ok; else ck "nmap OUI db" no "instala nmap"; fi

# Termux:API — opcional en Linux/Pi
SCAN=""
for p in \
  "$(command -v termux-wifi-scaninfo 2>/dev/null || true)" \
  /data/data/com.termux/files/usr/bin/termux-wifi-scaninfo
do
  [ -n "$p" ] && [ -x "$p" ] && SCAN="$p" && break
done
if [ -n "$SCAN" ]; then
  cko "termux-wifi-scaninfo (opcional)" ok
else
  cko "termux-wifi-scaninfo (opcional)" no "normal en Pi/PC — LAN no lo necesita"
fi

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

# supervisor (v4) running
if test -f logs/supervisor.pid && kill -0 "$(cat logs/supervisor.pid)" 2>/dev/null; then
  echo "  [ok]   supervisor corriendo"
else
  echo "  [FAIL] supervisor caído"; fail=1
fi

echo "== resultado: $([ $fail -eq 0 ] && echo TODO OK || echo 'hay fallos') =="
exit $fail
