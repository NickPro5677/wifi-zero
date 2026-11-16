# -*- coding: utf-8 -*-
"""Detección de runtime (Linux/Pi vs Termux) y rutas portables.

El host primario es un PC o Raspberry Pi (Debian/Ubuntu/Raspberry Pi OS).
Termux/Android queda como runtime opcional/legado. El escaneo Wi‑Fi cercano
vía Termux:API es secundario; en Linux el monitoreo principal es ARP/LAN.
"""
from __future__ import annotations

import os
import shutil
from functools import lru_cache

TERMUX_PREFIX = "/data/data/com.termux/files/usr"
ANDROID_IP = "/system/bin/ip"

# Rutas típicas de nmap OUI en distros Debian-like
_OUI_CANDIDATES = (
    os.path.join(TERMUX_PREFIX, "share", "nmap", "nmap-mac-prefixes"),
    "/usr/share/nmap/nmap-mac-prefixes",
    "/usr/local/share/nmap/nmap-mac-prefixes",
)

_NMAP_CANDIDATES = (
    os.path.join(TERMUX_PREFIX, "bin", "nmap"),
    "nmap",
)

_WIFI_SCAN_CANDIDATES = (
    os.path.join(TERMUX_PREFIX, "bin", "termux-wifi-scaninfo"),
    "termux-wifi-scaninfo",
)

_WIFI_CONN_CANDIDATES = (
    os.path.join(TERMUX_PREFIX, "bin", "termux-wifi-connectioninfo"),
    "termux-wifi-connectioninfo",
)

_BATTERY_CANDIDATES = (
    os.path.join(TERMUX_PREFIX, "bin", "termux-battery-status"),
    "termux-battery-status",
)

_NOTIFY_CANDIDATES = (
    os.path.join(TERMUX_PREFIX, "bin", "termux-notification"),
    "termux-notification",
)


def _first_existing(paths, *, executable=False):
    for p in paths:
        if not p:
            continue
        if os.path.sep in p or p.startswith("/"):
            if os.path.isfile(p) and (not executable or os.access(p, os.X_OK)):
                return p
        else:
            found = shutil.which(p)
            if found:
                return found
    return None


@lru_cache(maxsize=1)
def is_termux():
    """True si parece Termux/Android (prefix o binarios típicos)."""
    if os.environ.get("WZ_RUNTIME", "").lower() in ("termux", "android"):
        return True
    if os.environ.get("WZ_RUNTIME", "").lower() in ("linux", "pi", "debian"):
        return False
    if os.path.isdir(TERMUX_PREFIX):
        return True
    if os.path.isfile(ANDROID_IP):
        return True
    return False


@lru_cache(maxsize=1)
def is_linux_host():
    """Host Linux (Pi/PC): no Termux. Forzable con WZ_RUNTIME=linux."""
    return not is_termux()


def ip_cmd():
    """Binario `ip` (iproute2). En Android suele estar fuera del PATH de Termux."""
    env = os.environ.get("WZ_IP_CMD")
    if env and os.path.isfile(env):
        return env
    if os.path.isfile(ANDROID_IP) and os.access(ANDROID_IP, os.X_OK):
        return ANDROID_IP
    found = shutil.which("ip")
    if found:
        return found
    # último recurso: nombre en PATH (fallará en runtime si no existe)
    return "ip"


def nmap_bin():
    env = os.environ.get("WZ_NMAP")
    if env:
        return env
    return _first_existing(_NMAP_CANDIDATES, executable=True) or "nmap"


def oui_file():
    env = os.environ.get("WZ_OUI")
    if env and os.path.isfile(env):
        return env
    return _first_existing(_OUI_CANDIDATES) or _OUI_CANDIDATES[-1]


def wifi_scaninfo_bin():
    return os.environ.get("WZ_WIFI_SCANINFO") or _first_existing(
        _WIFI_SCAN_CANDIDATES, executable=True
    )


def wifi_conninfo_bin():
    return os.environ.get("WZ_WIFI_CONNINFO") or _first_existing(
        _WIFI_CONN_CANDIDATES, executable=True
    )


def battery_bin():
    return os.environ.get("WZ_BATTERY") or _first_existing(
        _BATTERY_CANDIDATES, executable=True
    )


def notify_bin():
    return os.environ.get("WZ_NOTIFY") or _first_existing(
        _NOTIFY_CANDIDATES, executable=True
    )


def wifi_scan_available():
    p = wifi_scaninfo_bin()
    return bool(p and os.path.isfile(p) and os.access(p, os.X_OK))


def recommended_bind():
    """En Pi/PC el panel se abre desde el teléfono → LAN; en Termux, loopback."""
    return "0.0.0.0" if is_linux_host() else "127.0.0.1"


def host_profile():
    """Perfil para /api/setup/status y docs/UX."""
    linux = is_linux_host()
    scan_ok = wifi_scan_available()
    return {
        "runtime": "linux" if linux else "termux",
        "is_linux_host": linux,
        "is_termux": not linux,
        "primary_role": "lan_brain" if linux else "phone_host",
        "recommended_bind": recommended_bind(),
        "wifi_nearby_optional": True,
        "wifi_scan_available": scan_ok,
        "lan_primary": True,
        "hints": _hints(linux, scan_ok),
    }


def _hints(linux, scan_ok):
    hints = []
    if linux:
        hints.append(
            "Host Linux/Pi: el monitoreo principal es ARP/LAN. "
            "Abre el panel desde el teléfono (PWA) contra la IP del Pi."
        )
        hints.append(
            "Elige bind 0.0.0.0 para acceder desde la LAN. "
            "HTTP sin TLS: solo en red de confianza (ver docs/SECURITY.md)."
        )
        hints.append(
            "Persiste WZ_SESSION_SECRET (p. ej. EnvironmentFile en systemd)."
        )
        if not scan_ok:
            hints.append(
                "Escaneo Wi‑Fi cercano (Termux:API) no disponible aquí — "
                "es opcional; el inventario de hosts no lo necesita."
            )
        hints.append(
            "En el teléfono: abre http://<IP-del-Pi>:8788 e instala como PWA."
        )
    else:
        hints.append(
            "Runtime Termux (legado/opcional): preferible mover el cerebro a un Pi/PC."
        )
        hints.append(
            "Bind 127.0.0.1 mantiene el Bearer fuera de la Wi‑Fi; "
            "0.0.0.0 solo en LAN de confianza."
        )
        if not scan_ok:
            hints.append(
                "Instala Termux:API + permisos de ubicación/Wi‑Fi cercanas "
                "si quieres el escaneo de redes cercanas."
            )
    return hints


def clear_cache():
    """Para tests: invalida caches de detección."""
    is_termux.cache_clear()
    is_linux_host.cache_clear()
