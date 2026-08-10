# -*- coding: utf-8 -*-
"""Threat scoring (v3): 0-100 por host y por AP, con criterios configurables.

v3 añade:
  - mapa de puertos peligrosos (exposición a servicios débiles/administrativos)
  - penalización por MAC localmente administrada (LAA = posible randomización)
  - sospecha por fabricante desconocido sin hostname
  - score_ap(): riesgo de punto de acceso (OPEN, oculto, twin, canal 13...)
"""
import sys
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "core"))

# puertos que suben sospecha por sí solos (servicios administrativos o débiles)
DANGEROUS_PORTS = {
    21: "ftp", 23: "telnet", 25: "smtp", 110: "pop3", 143: "imap",
    445: "smb", 1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker",
    3306: "mysql", 3389: "rdp", 5432: "postgres", 5900: "vnc", 6379: "redis",
    8081: "admin", 8443: "admin", 9090: "admin", 27017: "mongodb",
}
WEAK_SERVICES = ("telnet", "ftp", "upnp", "dns", "snmp", "tftp", "http-alt")


def _cfg(cfg, *keys, default=None):
    if not cfg:
        return default
    cur = cfg
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def is_randomized_mac(mac):
    """Bit localmente administrado del primer octeto ⇒ MAC randomizada (LAA)."""
    if not mac:
        return False
    try:
        return int(mac.replace(":", "").replace("-", "")[:2], 16) & 0x02 != 0
    except Exception:
        return False


def score_host(row, ports, trusted, cfg=None):
    """row: dict de `hosts`. Devuelve score 0-100 + tier."""
    w = {
        "untrusted": 25, "unknown": 10, "no_vendor": 15,
        "random_mac": 15, "per_port": 6, "max_ports": 30, "weak_svc": 10,
        "danger_port": 15, "random_thresh": 12,
    }
    for k, v in w.items():
        w[k] = int(_cfg(cfg, "threat", "weights", k, default=v))

    s = 0
    if trusted is False:
        s += w["untrusted"]
    elif trusted is None:
        s += w["unknown"]

    ven = (row.get("vendor") or "")
    if not ven or ven in ("?", "unknown"):
        s += w["no_vendor"]
        if not row.get("hostname"):
            s += 5

    if is_randomized_mac(row.get("mac")):
        s += w["random_mac"]

    s += min(w["max_ports"], len(ports) * w["per_port"])   # superficie expuesta
    for p in ports:
        if p.get("service", "").lower() in WEAK_SERVICES:
            s += w["weak_svc"]
        if p.get("port") in DANGEROUS_PORTS:
            s += w["danger_port"]
    if s >= 60:
        tier = "crit"
    elif s >= 30:
        tier = "warn"
    else:
        tier = "ok"
    return {"score": min(100, s), "tier": tier}


def score_ap(ap, twin=False, cfg=None):
    """Riesgo 0-100 de un punto de acceso visible."""
    s = 0
    enc = (ap.get("encryption") or "").upper()
    if enc in ("", "OPEN"):
        s += 40
    elif enc in ("WPA", "WEP"):
        s += 20
    if ap.get("hidden"):
        s += 15
    if twin:
        s += 25
    try:
        rssi = int(ap.get("rssi") or 0)
        if rssi >= -45:  # muy cerca ⇒ si es hostil, peor
            s += 10
        elif rssi <= -75:
            s += 5
    except Exception:
        pass
    chan = str(ap.get("channel") or "")
    if chan in ("13", "14"):  # canales fuera del estándar europeo común
        s += 5
    if s >= 60:
        tier = "crit"
    elif s >= 30:
        tier = "warn"
    else:
        tier = "ok"
    return {"score": min(100, s), "tier": tier}