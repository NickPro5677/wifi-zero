# -*- coding: utf-8 -*-
"""Configuración de wifi-zero.

Carga config.json (si existe) y lo fusiona sobre los defaults. Proporciona
acceso tipado y una función `validar` que detecta errores de configuración
antes de arrancar el monitor/panel.
"""
import json
import os
import logging

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

DEFAULTS = {
    "intervalos": {"lan": 60, "wifi": 120, "sv": 300},
    "notify": {"min_level": "warn", "channel": "wifi-zero"},
    "panel": {"port": 8788, "bind": "0.0.0.0", "auth": True, "user": "admin", "password": ""},
    "battery": {"eco_below": 35, "pause_below": 15},
    "scanner": {
        "ports_scan": [22, 53, 80, 123, 443, 445, 554, 1900, 5060, 5353, 8000, 8080, 8443, 8888, 9090, 49152],
        "nse_broadcast": True,
        "service_versions": True,
    },
    "pushes": {"enabled": False, "ntfy_url": "", "telegram_token": "", "telegram_chat": ""},
    "watchlist": [],
    "retention": {
        "signals": 7, "hosts_history": 14, "scores": 30,
        "stations": 7, "events": 30, "ports_closed": 7,
    },
    "gateway_watch": True,
    "threat": {
        "unknown_vendor_warn": True,
        "new_open_port": 15,
        "weights": {
            "untrusted": 25, "unknown": 10, "no_vendor": 15,
            "random_mac": 15, "per_port": 6, "max_ports": 30,
            "weak_svc": 10, "danger_port": 15,
        },
    },
}

VALID_LEVELS = {"info", "warn", "crit"}


def _deep_merge(base, over):
    """Merge dicts recursivo: over gana sobre base."""
    out = dict(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


class Config:
    def __init__(self, data=None, path=CONFIG_PATH):
        self.path = path
        loaded = {}
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
            except Exception as e:
                logging.getLogger("cfg").warning("config.json inválido (%s), usando defaults", e)
        self.data = _deep_merge(DEFAULTS, loaded)

    # conveniences ---------------------------------------------------------
    def get(self, *keys, default=None):
        cur = self.data
        for k in keys:
            if not isinstance(cur, dict) or k not in cur:
                return default
            cur = cur[k]
        return cur

    @property
    def lan_interval(self):
        return int(self.get("intervalos", "lan", default=60))

    @property
    def wifi_interval(self):
        return int(self.get("intervalos", "wifi", default=120))

    @property
    def sv_interval(self):
        return int(self.get("intervalos", "sv", default=300))

    @property
    def notify_min_level(self):
        return self.get("notify", "min_level", default="warn")

    @property
    def panel(self):
        return self.get("panel", default={})

    @property
    def battery(self):
        return self.get("battery", default={})

    @property
    def scanner_ports(self):
        return self.get("scanner", "ports_scan", default=DEFAULTS["scanner"]["ports_scan"])

    def validar(self):
        """Devuelve lista de problemas (vacía = OK)."""
        issues = []
        if self.notify_min_level not in VALID_LEVELS:
            issues.append(f"notify.min_level '{self.notify_min_level}' inválido")
        if not 0 < self.panel.get("port", 0) < 65536:
            issues.append("panel.port fuera de rango")
        if not all(0 < int(self.get("intervalos", k, default=0)) for k in ("lan", "wifi", "sv")):
            issues.append("intervalos.lan/wifi/sv deben ser > 0")
        if self.get("battery", "pause_below", default=0) >= self.get("battery", "eco_below", default=0):
            issues.append("battery.eco_below debe ser mayor que pause_below")
        ports = self.scanner_ports
        if not (isinstance(ports, list) and ports and all(0 < int(p) < 65536 for p in ports)):
            issues.append("scanner.ports_scan: lista de puertos 1-65535")
        if self.get("pushes", "enabled", default=False):
            if not (self.get("pushes", "ntfy_url") or
                    (self.get("pushes", "telegram_token") and self.get("pushes", "telegram_chat"))):
                issues.append("pushes.enabled=true sin ntfy_url ni telegram completo")
        return issues


def load():
    return Config()
