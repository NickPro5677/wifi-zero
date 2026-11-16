# -*- coding: utf-8 -*-
"""Healthchecks de wifi-zero (equivalente JSON de checks.sh)."""
from __future__ import annotations

import os
import shutil
import subprocess

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

import runtime  # noqa: E402


def _ok(name, ok, detail="", *, optional=False):
    return {
        "name": name,
        "ok": bool(ok),
        "detail": detail or ("ok" if ok else "fail"),
        "optional": bool(optional),
    }


def run_checks(port=8788, supervisor=None):
    """Lista de chequeos. Termux:API es opcional en Linux/Pi."""
    results = []
    linux = runtime.is_linux_host()
    ip_bin = runtime.ip_cmd()

    # cualquier iface con IP privada (wlan0/eth0/…)
    iface_ok, iface_detail = False, "sin ip privada"
    try:
        out = subprocess.run(
            [ip_bin, "-brief", "addr"],
            capture_output=True, text=True, timeout=3,
        )
        text = out.stdout or ""
        for line in text.splitlines():
            if any(p in line for p in ("192.168.", "10.", "172.")):
                # descartar loopback-like; 127. ya no matchea los prefijos
                iface_ok, iface_detail = True, line.strip()[:120]
                break
        if not iface_ok:
            iface_detail = (text.strip()[:120] or "sin IPv4 privada en ifaces")
    except Exception as e:
        iface_detail = str(e)
    results.append(_ok("interfaz LAN", iface_ok, iface_detail))

    ip_ok = bool(shutil.which(ip_bin) or (os.path.isfile(ip_bin) and os.access(ip_bin, os.X_OK)))
    results.append(_ok("ip (iproute2)", ip_ok, ip_bin))

    oui = runtime.oui_file()
    results.append(_ok("nmap OUI db", os.path.isfile(oui), oui))

    # Escaneo Wi‑Fi cercano: obligatorio solo en Termux; en Linux es opcional
    scan_bin = runtime.wifi_scaninfo_bin()
    scan_ok = bool(
        scan_bin and os.path.isfile(scan_bin) and os.access(scan_bin, os.X_OK)
    )
    if linux:
        detail = (
            scan_bin if scan_ok
            else "opcional — no instalado (normal en Pi/PC; LAN no lo necesita)"
        )
        # no marca el resumen como fallido
        results.append(_ok("termux-wifi-scaninfo (opcional)", True, detail, optional=True))
    else:
        results.append(_ok(
            "termux-wifi-scaninfo",
            scan_ok,
            scan_bin or "no encontrado (pkg install termux-api)",
        ))

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

    # solo fallan los chequeos no opcionales
    required = [r for r in results if not r.get("optional")]
    all_ok = all(r["ok"] for r in required)
    return {
        "ok": all_ok,
        "checks": results,
        "summary": "TODO OK" if all_ok else "hay fallos",
        "runtime": "linux" if linux else "termux",
    }


def make_backup(retain_days=7):
    """Snapshot consistente de data/wifi.db → data/backups/wifi-<ts>.db.

    Usa la API de backup de sqlite3 (WAL-safe). Si falla, hace
    ``PRAGMA wal_checkpoint(TRUNCATE)`` y copia como fallback.
    """
    import sqlite3
    import time

    src = os.path.join(BASE_DIR, "data", "wifi.db")
    bak_dir = os.path.join(BASE_DIR, "data", "backups")
    os.makedirs(bak_dir, exist_ok=True)
    if not os.path.isfile(src):
        return {"ok": False, "error": "no existe data/wifi.db"}
    dest = os.path.join(bak_dir, time.strftime("wifi-%Y%m%d-%H%M.db"))
    try:
        src_con = sqlite3.connect(src, timeout=8)
        try:
            dst_con = sqlite3.connect(dest)
            try:
                src_con.backup(dst_con)
            finally:
                dst_con.close()
        finally:
            src_con.close()
    except Exception as e:
        # fallback: checkpoint + copy (mejor que un cp a ciegas)
        try:
            con = sqlite3.connect(src, timeout=8)
            try:
                con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            finally:
                con.close()
            shutil.copy2(src, dest)
        except Exception as e2:
            return {"ok": False, "error": f"backup falló: {e}; fallback: {e2}"}
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
