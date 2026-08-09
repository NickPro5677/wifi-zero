# -*- coding: utf-8 -*-
"""Threat scoring por host (F2). 0-100 con criterio configurable."""
import sys
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "core"))


def score_host(row, ports, trusted, cfg=None):
    """row: dict de `hosts`. Devuelve score 0-100 + tier."""
    s = 0
    if trusted is False:
        s += 25                     # MAC explícitamente no confiable
    elif trusted is None:
        s += 10                     # desconocido (no whitelisted)

    ven = (row.get("vendor") or "")
    if not ven or ven == "?":
        s += 15
    elif row.get("mac") and ven.lower() in ("unknown",):
        s += 15

    s += min(30, len(ports) * 6)    # servicios expuestos
    if any(p.get("service") in ("telnet", "ftp", "upnp", "dns") for p in ports):
        s += 10
    if s >= 60:
        tier = "crit"
    elif s >= 30:
        tier = "warn"
    else:
        tier = "ok"
    return {"score": min(100, s), "tier": tier}