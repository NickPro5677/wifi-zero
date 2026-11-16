# -*- coding: utf-8 -*-
"""Healthchecks de wifi-zero (equivalente JSON de checks.sh)."""
from __future__ import annotations

import os
import shutil
import subprocess

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PREFIX = "/data/data/com.termux/files/usr"
IP_CMD = "/system/bin/ip"
OUI = os.path.join(PREFIX, "share", "nmap", "nmap-mac-prefixes")
WIFI_SCAN = os.path.join(PREFIX, "bin", "termux-wifi-scaninfo")


def _ok(name, ok, detail=""):
    return {"name": name, "ok": bool(ok), "detail": detail or ("ok" if ok else "fail")}


def run_checks(port=8788, supervisor=None):
    """Lista de chequeos. Tolerante fuera de Termux (marca fail, no explota)."""
    results = []

    # interfaz wlan0 con IP privada
    wlan_ok, wlan_detail = False, "sin ip"
    try:
        out = subprocess.run(
            [IP_CMD, "-brief", "addr", "show", "wlan0"],
            capture_output=True, text=True, timeout=3,
        )
        text = out.stdout or ""
        if any(p in text for p in ("192.168.", "10.", "172.")):
            wlan_ok, wlan_detail = True, text.strip()[:120]
        else:
            wlan_detail = text.strip()[:120] or "wlan0 sin IPv4 privada"
    except Exception as e:
        wlan_detail = str(e)
    results.append(_ok("interfaz wlan0", wlan_ok, wlan_detail))

    results.append(_ok("ip (system)", os.path.isfile(IP_CMD) and os.access(IP_CMD, os.X_OK), IP_CMD))
    results.append(_ok("nmap OUI db", os.path.isfile(OUI), OUI))
    results.append(_ok("termux-wifi-scaninfo",
                       os.path.isfile(WIFI_SCAN) and os.access(WIFI_SCAN, os.X_OK), WIFI_SCAN))

    # python + sqlite3 + import db
    try:
        import sqlite3  # noqa: F401
        import db
        con = db.connect()
        n = len(db.all_hosts(con))
        con.close()
        results.append(_ok("python + sqlite3", True, f"{n} hosts"))
        results.append(_ok("base de datos", True, os.path.join(BASE_DIR, "data", "wifi.db")))
    except Exception as e:
        results.append(_ok("python + sqlite3", False, str(e)))
        results.append(_ok("base de datos", False, str(e)))

    # panel escuchando
    panel_ok = False
    try:
        import urllib.request
        urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=3)
        panel_ok = True
    except Exception as e:
        # /api/health puede exigir auth; cualquier respuesta HTTP cuenta
        try:
            import urllib.error
            if isinstance(e, urllib.error.HTTPError):
                panel_ok = True
        except Exception:
            pass
    results.append(_ok("panel web", panel_ok, f"127.0.0.1:{port}"))

    mon_ok = False
    detail = "monitor off"
    if supervisor is not None:
        st = supervisor.status()
        mon_ok = bool(st.get("monitor_running") or st.get("monitor_thread"))
        detail = st.get("mode", detail)
    else:
        pidf = os.path.join(BASE_DIR, "logs", "monitor.pid")
        try:
            pid = int(open(pidf).read().strip())
            os.kill(pid, 0)
            mon_ok, detail = True, f"pid {pid}"
        except Exception:
            pass
    results.append(_ok("monitor corriendo", mon_ok, detail))

    all_ok = all(r["ok"] for r in results)
    return {"ok": all_ok, "checks": results, "summary": "TODO OK" if all_ok else "hay fallos"}


def make_backup(retain_days=7):
    """Copia data/wifi.db → data/backups/wifi-<ts>.db y poda antiguos."""
    import time
    src = os.path.join(BASE_DIR, "data", "wifi.db")
    bak_dir = os.path.join(BASE_DIR, "data", "backups")
    os.makedirs(bak_dir, exist_ok=True)
    if not os.path.isfile(src):
        return {"ok": False, "error": "no existe data/wifi.db"}
    dest = os.path.join(bak_dir, time.strftime("wifi-%Y%m%d-%H%M.db"))
    shutil.copy2(src, dest)
    # poda
    cutoff = time.time() - retain_days * 86400
    removed = []
    for name in os.listdir(bak_dir):
        if not name.startswith("wifi-") or not name.endswith(".db"):
            continue
        path = os.path.join(bak_dir, name)
        try:
            if os.path.getmtime(path) < cutoff:
                os.remove(path)
                removed.append(name)
        except OSError:
            pass
    recent = sorted(
        (n for n in os.listdir(bak_dir) if n.startswith("wifi-")),
        reverse=True,
    )[:5]
    return {"ok": True, "path": dest, "removed": removed, "recent": recent}
