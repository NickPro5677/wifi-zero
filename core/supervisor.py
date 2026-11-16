# -*- coding: utf-8 -*-
"""Supervisor v4: posee el panel HTTP y el ciclo de vida del monitor.

El usuario arranca una sola vez (`python3 -m core` / ``./start_all.sh``) y
luego opera todo desde la PWA: start/stop/restart, config, password, checks.
"""
from __future__ import annotations

import os
import signal
import sys
import threading
import time
import traceback

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "core"))
sys.path.insert(0, os.path.join(BASE_DIR, "scanner"))

import config  # noqa: E402
from log import setup as log_setup, get as log_get  # noqa: E402

log_setup("supervisor", level=20)
LOGGER = log_get("supervisor")

PIDFILE = os.path.join(BASE_DIR, "logs", "supervisor.pid")
MONITOR_PIDFILE = os.path.join(BASE_DIR, "logs", "monitor.pid")


class Supervisor:
    """Estado compartido entre HTTP handler y el hilo del monitor."""

    def __init__(self):
        self.cfg = config.load()
        self._lock = threading.RLock()
        self._mon_thread = None
        self._monitor = None
        self._stop_evt = threading.Event()
        self._last_error = None
        self._started_at = None
        self._mode = "stopped"  # stopped | running | paused | eco | offline_wifi | error
        self._manual_pause = False
        self._cfg_generation = 0

    # -------------------------------------------------------------- config
    def reload_config(self):
        with self._lock:
            self.cfg = config.load()
            self._cfg_generation += 1
            if self._monitor is not None:
                self._monitor.cfg = self.cfg
                try:
                    self._monitor.rs.cfg = self.cfg
                except Exception:
                    pass
            return self.cfg

    def apply_config(self, data, path=None):
        """Persiste `data` en config.json, valida y recarga en caliente."""
        cfg = config.Config(data=data, path=path or config.CONFIG_PATH)
        issues = cfg.validar()
        if issues:
            return False, issues
        cfg.save()
        self.reload_config()
        return True, []

    # ----------------------------------------------------------- lifecycle
    def status(self):
        with self._lock:
            alive = bool(self._mon_thread and self._mon_thread.is_alive())
            mode = self._mode
            if self._manual_pause:
                mode = "paused"
            elif alive and self._monitor is not None:
                mode = getattr(self._monitor, "mode", mode) or mode
            elif not alive:
                mode = "error" if self._last_error else "stopped"
            bat = None
            charging = None
            try:
                from monitor import battery_state
                charging, bat = battery_state()
            except Exception:
                pass
            return {
                "ok": True,
                "mode": mode,
                "monitor_running": alive and not self._manual_pause,
                "monitor_thread": alive,
                "manual_pause": self._manual_pause,
                "started_at": self._started_at,
                "last_error": self._last_error,
                "battery_pct": bat,
                "charging": charging,
                "cfg_generation": self._cfg_generation,
                "setup_needed": config.setup_needed(self.cfg),
                "version": "4.0.0",
            }

    def start_monitor(self, force=False):
        with self._lock:
            if self._mon_thread and self._mon_thread.is_alive():
                if self._manual_pause:
                    self._manual_pause = False
                    if self._monitor is not None:
                        self._monitor.manual_pause = False
                    self._mode = "running"
                    return True, "reanudado"
                if not force:
                    return True, "ya en marcha"
                self._stop_monitor_locked()
            self._stop_evt.clear()
            self._manual_pause = False
            self._last_error = None
            self._mode = "running"

            def _run():
                try:
                    from monitor import Monitor
                    mon = Monitor(self.cfg, stop_event=self._stop_evt, supervisor=self)
                    with self._lock:
                        self._monitor = mon
                        self._started_at = int(time.time())
                    mon.loop()
                except Exception as e:
                    LOGGER.error("monitor crash: %s\n%s", e, traceback.format_exc())
                    with self._lock:
                        self._last_error = str(e)
                        self._mode = "error"
                finally:
                    with self._lock:
                        self._monitor = None
                        if self._mode not in ("error", "paused"):
                            self._mode = "stopped"
                    try:
                        if os.path.exists(MONITOR_PIDFILE):
                            os.remove(MONITOR_PIDFILE)
                    except OSError:
                        pass

            self._mon_thread = threading.Thread(target=_run, name="wz-monitor", daemon=True)
            self._mon_thread.start()
            return True, "monitor arrancado"

    def _stop_monitor_locked(self):
        self._stop_evt.set()
        self._manual_pause = False
        mon = self._monitor
        if mon is not None:
            mon.request_stop()
        t = self._mon_thread
        self._mode = "stopped"
        if t and t.is_alive():
            t.join(timeout=8)
        self._mon_thread = None
        self._monitor = None

    def stop_monitor(self):
        with self._lock:
            if not (self._mon_thread and self._mon_thread.is_alive()):
                self._mode = "stopped"
                return True, "ya parado"
            self._stop_monitor_locked()
            return True, "monitor detenido"

    def pause_monitor(self):
        with self._lock:
            if not (self._mon_thread and self._mon_thread.is_alive()):
                return False, "monitor no está en marcha"
            self._manual_pause = True
            if self._monitor is not None:
                self._monitor.manual_pause = True
            self._mode = "paused"
            return True, "monitor en pausa"

    def resume_monitor(self):
        return self.start_monitor()

    def restart_monitor(self):
        self.stop_monitor()
        time.sleep(0.3)
        return self.start_monitor(force=True)

    def trigger_scan(self):
        """Una pasada LAN+WiFi en hilo aparte (no bloquea el panel)."""
        def work():
            try:
                from monitor import Monitor
                Monitor(self.cfg).run(deep_sv=True)
            except Exception as e:
                LOGGER.error("scan manual: %s", e)
                try:
                    import db
                    db.add_event(db.connect(), "error", "warn", f"escaneo manual: {e}")
                except Exception:
                    pass
        threading.Thread(target=work, name="wz-scan", daemon=True).start()
        return True, "escaneo lanzado"

    def set_mode(self, mode):
        with self._lock:
            if mode in ("running", "paused", "eco", "offline_wifi", "error", "stopped"):
                self._mode = mode


# singleton del proceso
SUPERVISOR = Supervisor()


def main(argv=None):
    """Arranca panel + monitor (auto-start salvo setup pendiente)."""
    argv = argv or sys.argv[1:]
    os.makedirs(os.path.join(BASE_DIR, "logs"), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, "data"), exist_ok=True)

    issues = SUPERVISOR.cfg.validar()
    # password vacía es válida en first-run; filtramos ese caso
    soft = [i for i in issues if "password" not in i.lower()]
    if soft:
        LOGGER.error("config inválida: %s", soft)
        print("config inválida:", soft, file=sys.stderr)
        return 1

    with open(PIDFILE, "w") as f:
        f.write(str(os.getpid()))

    def _sig(_s, _f):
        LOGGER.info("señal %s — deteniendo", _s)
        SUPERVISOR.stop_monitor()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)

    auto = "--no-monitor" not in argv
    if auto and not config.setup_needed(SUPERVISOR.cfg):
        SUPERVISOR.start_monitor()
        LOGGER.info("monitor auto-start")
    else:
        LOGGER.info("setup pendiente o --no-monitor: solo panel")

    # server.serve_forever bloquea
    import server
    server.attach_supervisor(SUPERVISOR)
    server.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
