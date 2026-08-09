# -*- coding: utf-8 -*-
"""wifi-zero monitor (F2/F5): bucle continuo integrado.

Cada ciclo: escanea LAN (n) y WiFi (wifi), pasa los cambios por el motor de
reglas (Rules) → eventos en SQLite → notificaciones. Es battery-aware y cae
a modo silencio si el teléfono se desenchufa con poca batería; además respeta
el estado real de la red (si el supplicant NO está COMPLETED no escanea).
"""
import json
import os
import subprocess
import sys
import time

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "core"))
sys.path.insert(0, os.path.join(BASE_DIR, "scanner"))

import db  # noqa: E402
import lan_scan  # noqa: E402
import wifi_track  # noqa: E402
import config  # noqa: E402
from log import setup as log_setup, get as log_get  # noqa: E402
from rules import Rules  # noqa: E402
from notify import Notifier  # noqa: E402

log_setup("monitor", level=10 if os.environ.get("WZ_DEBUG") else 20)
LOGGER = log_get("monitor")

PIDFILE = os.path.join(BASE_DIR, "logs", "monitor.pid")

BATTERY_BIN = "/data/data/com.termux/files/usr/bin/termux-battery-status"


def battery_state():
    """(loaded, pct); ante cualquier fallo supone sano."""
    try:
        out = subprocess.run([BATTERY_BIN], capture_output=True, text=True, timeout=4)
        if out.returncode == 0 and out.stdout.strip():
            d = json.loads(out.stdout)
            return d.get("status") == "CHARGING", d.get("percentage", 100)
    except Exception:
        pass
    return True, 100


def wifi_gate():
    st = wifi_track.get_link()
    return bool(st and st.get("connected"))


class Monitor:
    def __init__(self, cfg):
        self.cfg = cfg
        self.con = db.connect()
        self.notifier = Notifier(cfg)
        self.rs = Rules(self.con, cfg, self._emit)
        self._first = True

    def _emit(self, rule, level, message, ip=None, mac=None):
        db.add_event(self.con, rule, level, message, ip=ip, mac=mac)
        LOGGER.info("[%s·%s] %s", rule, level, message)
        self.notifier(rule, level, message, ip=ip, mac=mac)
        return True

    def _is_critical(self, mac):
        for e in self.cfg.get("watchlist", default=[]):
            if e.get("mac", "").lower() == (mac or "").lower():
                return e.get("label", "crítico")
        return None

    # -------------------------------------------------------------- LAN cycle
    def _cycle_lan(self):
        before = {h["ip"]: h for h in db.all_hosts(self.con)}
        try:
            lan_scan.scan_once()
        except Exception as e:
            LOGGER.error("lan err %r", e)

        cur = {h["ip"]: h for h in db.all_hosts(self.con)}
        seen = set()
        if not self._first:
            for ip, h in cur.items():
                if not h.get("state"):
                    continue
                seen.add(ip)
                prev = before.get(ip)
                self.rs.host_seen(
                    ip, h.get("mac"), vendor=h.get("vendor"),
                    is_new=prev is None,
                    replaced_mac=prev.get("mac") if prev else None,
                )
            # offline: antes estaba y ahora ya no está
            for ip, h in before.items():
                if h.get("state") == 1 and ip not in cur:
                    self.rs.host_offline(ip, h.get("mac"), self._is_critical(h.get("mac")))
        # puertos que se abrieron en este mismo ciclo
        for p in db.all_ports(self.con):
            if p["first_seen"] == p["last_seen"]:
                self.rs.port_new(p["ip"], p["port"], p.get("service"))

    # ------------------------------------------------------------- WiFi
    def _cycle_wifi(self):
        try:
            found, new_aps = wifi_track.track_once()
        except Exception as e:
            LOGGER.error("wifi err %r", e)
            return
        if self._first:
            return
        for ap in new_aps:
            if not ap.get("bssid"):
                continue
            self.rs.ap_new(ap)
            prev = self.con.execute("SELECT encryption FROM aps WHERE bssid=?",
                                    (ap["bssid"],)).fetchone()
            if prev and prev["encryption"] and prev["encryption"] != ap.get("encryption"):
                self.rs.ap_encryption_downgrade(ap, prev["encryption"], ap.get("encryption"))
        # SSIDs duplicados (posible evil-twin)
        seen_ssid, dups = set(), set()
        for a in found:
            s = (a.get("ssid") or "").strip()
            if not s or s.startswith("<"):
                continue
            if s in seen_ssid:
                dups.add(s)
            seen_ssid.add(s)
        for s in dups:
            self.rs.ap_twin(s)

    # ------------------------------------------------------------- power gate
    def _should_scan(self):
        charging, pct = battery_flush()
        if charging or pct >= self.cfg.battery.get("pause_below", 15):
            return True
        LOGGER.info("batería %d%% desenchufada — pausa de escaneo", pct)
        return False

    # ------------------------------------------------------------------ loop
    def run(self):
        """Una vuelta completa (usado por el loop y por la API /scan)."""
        self._cycle_lan()
        self._cycle_wifi()
        self._first = False

    def loop(self):
        with open(PIDFILE, "w") as f:
            f.write(str(os.getpid()))
        LOGGER.info("monitor pid %s — LAN cada %ss, WiFi cada %ss",
                    os.getpid(), self.cfg.lan_interval, self.cfg.wifi_interval)
        nxt = {}
        while True:
            t = time.time()
            if not wifi_gate():
                LOGGER.info("sin WiFi (supplicant inactive) — pausado")
            elif self._should_scan() and t >= nxt.get("lan", 0):
                try:
                    self.run()
                except Exception as e:
                    LOGGER.error("cycle err %r", e)
                nxt["lan"] = t + self.cfg.lan_interval
            time.sleep(5)


def battery_flush():
    """alias → battery_state() (parte del loop y de tests)."""
    return battery_state()


def stop():
    if os.path.exists(PIDFILE):
        try:
            pid = int(open(PIDFILE).read().strip())
            os.kill(pid, 15)
            LOGGER.info("detenido %s", pid)
        except Exception:
            pass
        try:
            os.remove(PIDFILE)
        except OSError:
            pass


if __name__ == "__main__":
    cfg = config.load()
    issues = cfg.validar()
    if issues:
        LOGGER.error("config inválida: %s", issues)
        sys.exit(1)
    if "stop" in sys.argv:
        stop()
    else:
        Monitor(cfg).loop()