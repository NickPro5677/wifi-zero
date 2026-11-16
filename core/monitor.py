# -*- coding: utf-8 -*-
"""wifi-zero monitor (F2/F5/v4): bucle continuo integrado.

Cada ciclo: escanea LAN (n) y WiFi (wifi), pasa los cambios por el motor de
reglas (Rules) → eventos en SQLite → notificaciones. Es battery-aware y cae
a modo silencio si el teléfono se desenchufa con poca batería; además respeta
el estado real de la red (si el supplicant NO está COMPLETED no escanea).

v4:
  - intervalos LAN y WiFi independientes (`intervalos.wifi`)
  - stop cooperativo (Event) para el supervisor
  - modo operativo reportado (running/eco/paused/offline_wifi)
  - downgrade de cifrado en APs existentes (prev_encryption del scan)
"""
import json
import os
import subprocess
import sys
import threading
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
from threat import is_randomized_mac  # noqa: E402

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


def battery_flush():
    """alias → battery_state() (parte del loop y de tests)."""
    return battery_state()


def wifi_gate():
    st = wifi_track.get_link()
    return bool(st and st.get("connected"))


class Monitor:
    def __init__(self, cfg, stop_event=None, supervisor=None):
        self.cfg = cfg
        self.con = db.connect()
        self.notifier = Notifier(cfg)
        self.rs = Rules(self.con, cfg, self._emit)
        self._first = True
        self._next_sv = 0.0
        self._next_prune = time.time() + 3600
        self._eco = False
        self._stop = stop_event or threading.Event()
        self.supervisor = supervisor
        self.manual_pause = False
        self.mode = "running"

    def request_stop(self):
        self._stop.set()

    def _stopped(self):
        return self._stop.is_set()

    def _set_mode(self, mode):
        self.mode = mode
        if self.supervisor is not None:
            try:
                self.supervisor.set_mode(mode)
            except Exception:
                pass

    def _emit(self, rule, level, message, ip=None, mac=None):
        # muted_rules: {rule: until_ts} — 0 o ausente = no mute; >now = activo; -1 = forever
        muted = self.cfg.get("muted_rules", default={}) or {}
        until = muted.get(rule)
        if until is not None:
            try:
                until = int(until)
            except (TypeError, ValueError):
                until = 0
            if until < 0 or until > time.time():
                LOGGER.debug("regla %s silenciada hasta %s", rule, until)
                return False
        db.add_event(self.con, rule, level, message, ip=ip, mac=mac)
        LOGGER.info("[%s·%s] %s", rule, level, message)
        self.notifier(rule, level, message, ip=ip, mac=mac)
        return True

    def _is_critical(self, mac):
        for e in self.cfg.get("watchlist", default=[]):
            if e.get("mac", "").lower() == (mac or "").lower():
                return e.get("label", "crítico")
        return None

    # ------------------------------------------------------------- power gate
    def _power_profile(self):
        """Devuelve (pause, eco, pct). pause si desenchufado bajo pause_below."""
        charging, pct = battery_flush()
        pause = (not charging and pct <= int(self.cfg.battery.get("pause_below", 15)))
        eco = (not charging and pct <= int(self.cfg.battery.get("eco_below", 35)))
        if pause:
            LOGGER.warning("batería %d%% desenchufada — pausa (pause_below)", pct)
        elif eco and not self._eco:
            LOGGER.warning("batería %d%% desenchufada — modo eco (intervalos ×2, sin -sV)", pct)
        elif self._eco and not eco:
            LOGGER.info("batería recuperada (%d%%) — modo normal", pct)
        self._eco = eco
        return pause, eco, pct

    # -------------------------------------------------------------- LAN cycle
    def _cycle_lan(self, deep_sv):
        before = {h["ip"]: h for h in db.all_hosts(self.con)}
        try:
            if os.environ.get("WZ_ECO") == "1" or self._eco:
                os.environ["WZ_ECO"] = "1"
            snap = lan_scan.scan_once(cfg=self.cfg, deep=deep_sv)
            if not self._eco:
                os.environ.pop("WZ_ECO", None)
        except Exception as e:
            LOGGER.error("lan err %r", e)
            return

        alive_now = set(snap.get("live", {}))
        macs = snap.get("live", {})
        cur = {h["ip"]: h for h in db.all_hosts(self.con)}

        if not self._first:
            # online: nuevos y re-identificaciones
            for ip in alive_now:
                h = cur.get(ip, {})
                prev = before.get(ip)
                is_new = prev is None
                self.rs.host_seen(
                    ip, h.get("mac"), vendor=h.get("vendor"),
                    is_new=is_new,
                    replaced_mac=prev.get("mac") if prev else None,
                )
                if is_new and is_randomized_mac(h.get("mac")):
                    self.rs.mac_randomized(ip, h.get("mac"), h.get("vendor"))
            # offline por transición de estado: antes con línea, ahora no visible
            for ip, h in before.items():
                if h.get("state") == 1 and ip not in alive_now:
                    self.rs.host_offline(ip, h.get("mac"), self._is_critical(h.get("mac")))
        # conflictos de IP en el snapshot (2+ MACs para la misma IP)
        for ip, ip_macs in (snap.get("conflicts") or {}).items():
            self.rs.ip_conflict(ip, list(ip_macs))
        # vigilancia del gateway (cambio de MAC = MITM clásico)
        if self.cfg.get("gateway_watch", default=True):
            self._watch_gateway(snap.get("gateway"), macs)
        # puertos que se abrieron en este mismo ciclo
        for p in db.all_ports(self.con):
            if p["first_seen"] == p["last_seen"]:
                self.rs.port_new(p["ip"], p["port"], p.get("service"))

    def _watch_gateway(self, gw_ip, macs):
        if not gw_ip:
            return
        gw_mac = macs.get(gw_ip)
        if not gw_mac:
            return
        last = self.con.execute(
            "SELECT info FROM runs WHERE kind='gateway' ORDER BY id DESC LIMIT 1").fetchone()
        old_ip, old_mac = None, None
        if last and last["info"]:
            parts = last["info"].split("|", 1)
            if len(parts) == 2:
                old_ip, old_mac = parts
        if old_mac and old_mac != gw_mac:
            self.rs.gateway_changed(old_mac, gw_mac, gw_ip)
        db.log_run(self.con, "gateway", info=f"{gw_ip}|{gw_mac}")
        if gw_mac:
            db.upsert_host(self.con, gw_ip, mac=gw_mac,
                           vendor=lan_scan.mac_vendor(gw_mac), state=1)

    def _record_scores(self):
        try:
            hosts = db.hosts_with_threat(self.con, self.cfg)
        except Exception as e:
            LOGGER.error("scores err %r", e)
            return
        batch = [h for h in hosts if h.get("state") or h.get("score", 0) >= 30]
        if batch:
            db.record_scores(self.con, batch)

    # ------------------------------------------------------------- WiFi
    def _cycle_wifi(self):
        try:
            found, new_aps = wifi_track.track_once()
        except Exception as e:
            LOGGER.error("wifi err %r", e)
            return
        if self._first:
            return
        new_bssids = {a.get("bssid") for a in new_aps if a.get("bssid")}
        for ap in found:
            if not ap.get("bssid"):
                continue
            if ap.get("bssid") in new_bssids:
                self.rs.ap_new(ap)
            prev_enc = ap.get("prev_encryption")
            new_enc = ap.get("encryption")
            if prev_enc and new_enc and prev_enc != new_enc:
                # solo alertar si es un downgrade real
                order = {"OPEN": 0, "WEP": 1, "WPA": 2, "WPA2": 3, "WPA3": 4}
                if order.get(new_enc, 0) < order.get(prev_enc, 0):
                    self.rs.ap_encryption_downgrade(ap, prev_enc, new_enc)
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

    # ------------------------------------------------------------------ loop
    def run(self, deep_sv=False, do_lan=True, do_wifi=True):
        """Una vuelta (LAN y/o WiFi). Usado por el loop y por la API /scan."""
        if do_lan:
            self._cycle_lan(deep_sv)
        if do_wifi:
            self._cycle_wifi()
        self._first = False

    def loop(self):
        os.makedirs(os.path.dirname(PIDFILE), exist_ok=True)
        with open(PIDFILE, "w") as f:
            f.write(str(os.getpid()))
        LOGGER.info("monitor pid %s — LAN %ss, sv %ss, WiFi %ss",
                    os.getpid(), self.cfg.lan_interval, self.cfg.sv_interval,
                    self.cfg.wifi_interval)
        nxt = {"lan": 0.0, "wifi": 0.0}
        while not self._stopped():
            t = time.time()
            if self.manual_pause:
                self._set_mode("paused")
                time.sleep(1)
                continue
            if not wifi_gate():
                LOGGER.info("sin WiFi (supplicant inactive) — pausado")
                self._set_mode("offline_wifi")
            else:
                pause, eco, _pct = self._power_profile()
                if pause:
                    self._set_mode("paused")
                    # sleep en trozos para respetar stop
                    for _ in range(15):
                        if self._stopped():
                            break
                        time.sleep(1)
                    continue
                self._set_mode("eco" if eco else "running")
                lan_iv = self.cfg.lan_interval * (2 if eco else 1)
                wifi_iv = self.cfg.wifi_interval * (2 if eco else 1)
                sv_iv = self.cfg.sv_interval * (2 if eco else 1)
                did = False
                if t >= nxt.get("lan", 0):
                    deep = (t >= self._next_sv)
                    if deep:
                        self._next_sv = t + sv_iv
                    try:
                        self.run(deep_sv=deep, do_lan=True, do_wifi=False)
                    except Exception as e:
                        LOGGER.error("lan cycle err %r", e)
                    nxt["lan"] = t + lan_iv
                    self._record_scores()
                    did = True
                if t >= nxt.get("wifi", 0):
                    try:
                        self.run(deep_sv=False, do_lan=False, do_wifi=True)
                    except Exception as e:
                        LOGGER.error("wifi cycle err %r", e)
                    nxt["wifi"] = t + wifi_iv
                    did = True
                if did and t >= self._next_prune:
                    try:
                        removed = db.prune(self.con)
                        LOGGER.info("prune: %s", removed)
                    except Exception as e:
                        LOGGER.error("prune err %r", e)
                    self._next_prune = t + 86400
            for _ in range(5):
                if self._stopped():
                    break
                time.sleep(1)
        LOGGER.info("monitor loop fin")
        self._set_mode("stopped")


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
