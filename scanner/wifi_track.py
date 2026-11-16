# -*- coding: utf-8 -*-
"""Wi-Fi tracker — Termux:API pasiva (sin root, sin modo monitor).

Lee solo lo que Android expone legalmente vía:
  - `termux-wifi-scaninfo`  → redes cercanas (SSID, BSSID, canal, RSSI, caps)
  - `termux-wifi-connectioninfo` → enlace actual del teléfono

No captura handshakes, no deauth, no spoofing, no cracking. Los campos
devueltos se limitan a la lista LEGAL_FIELDS (información de beacon/OS).
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "core"))
sys.path.insert(0, os.path.join(BASE_DIR, "scanner"))
import db  # noqa: E402
from lan_scan import mac_vendor  # noqa: E402

log = logging.getLogger("wifi")

_PREFIX = "/data/data/com.termux/files/usr/bin"
SCANINFO = os.environ.get(
    "WZ_WIFI_SCANINFO",
    os.path.join(_PREFIX, "termux-wifi-scaninfo"),
)
CONNINFO = os.environ.get(
    "WZ_WIFI_CONNINFO",
    os.path.join(_PREFIX, "termux-wifi-connectioninfo"),
)

# Campos legales / públicos reportados por el SO (beacon + ScanResult).
# Nunca se almacenan ni exponen passwords, PMK, handshakes ni payloads.
LEGAL_FIELDS = (
    "ssid",
    "bssid",
    "frequency_mhz",
    "channel",
    "band",
    "rssi",
    "encryption",
    "cipher",
    "capabilities",
    "timestamp",
    "hidden",
    "vendor",
    "bandwidth",
    "center_frequency",
    "channel_utilization",
    "dfs",
)

SCAN_DISCLAIMER = (
    "Escaneo pasivo vía Termux:API / Android Wi‑Fi scan. "
    "Solo campos reportados por el SO (SSID, BSSID, frecuencia/canal, "
    "RSSI, capabilities/cifrado). Requiere Termux:API + permisos de "
    "ubicación / Wi‑Fi cercanas. Sin modo monitor, deauth ni cracking."
)


def _run(exe, timeout=15):
    """Ejecuta un binario Termux:API. Devuelve (data|None, error|None)."""
    try:
        out = subprocess.run(
            [exe], capture_output=True, text=True, timeout=timeout
        )
        if out.returncode != 0:
            err = (out.stderr or out.stdout or f"exit {out.returncode}").strip()
            log.debug("error %s rc=%s: %s", exe, out.returncode, err[:200])
            return None, err or f"exit {out.returncode}"
        raw = (out.stdout or "").strip()
        if not raw:
            return None, "respuesta vacía (¿permisos de ubicación/Wi‑Fi?)"
        return json.loads(raw), None
    except FileNotFoundError:
        return None, f"no encontrado: {exe} (instala termux-api)"
    except subprocess.TimeoutExpired:
        return None, f"timeout {timeout}s"
    except json.JSONDecodeError as e:
        return None, f"JSON inválido: {e}"
    except Exception as e:
        log.debug("error %s: %s", exe, e)
        return None, str(e)


def parse_capabilities(caps):
    """Convierte una capabilities string en dict estructurado."""
    enc = "OPEN"
    cipher = None
    flags = set()
    if caps:
        for m in str(caps).replace("[", " ").replace("]", " ").split():
            if m:
                flags.add(m)
        # SAE = WPA3-Personal aunque Android no ponga el literal "WPA3"
        if "WPA3" in caps or "SAE" in caps:
            enc = "WPA3"
        elif "WPA2" in caps or "RSN" in caps:
            enc = "WPA2"
        elif "WPA" in caps:
            enc = "WPA"
        elif "WEP" in caps:
            enc = "WEP"
        if "CCMP" in caps or "GCMP" in caps:
            cipher = "CCMP" if "CCMP" in caps else "GCMP"
        if "TKIP" in caps:
            cipher = cipher or "TKIP"
    return {"encryption": enc, "cipher": cipher, "raw": caps, "flags": flags}


def channel_of(freq):
    if freq and 2412 <= freq <= 2484:
        return (freq - 2412) // 5 + 1
    if freq and 5180 <= freq <= 5825:
        return (freq - 5180) // 5 + 36
    if freq and 5955 <= freq <= 7115:
        return (freq - 5955) // 5 + 1
    return None


def band_of(freq):
    if not freq:
        return None
    if 2400 <= freq <= 2500:
        return "2.4GHz"
    if 5150 <= freq <= 5925:
        return "5GHz"
    if 5925 <= freq <= 7125:
        return "6GHz"
    return "?"


def _norm_freq(a):
    f = a.get("frequency_mhz")
    if f is None:
        f = a.get("frequency")
    try:
        return int(f) if f is not None else None
    except (TypeError, ValueError):
        return None


def _norm_rssi(a):
    r = a.get("rssi")
    if r is None:
        r = a.get("level")
    try:
        return int(r) if r is not None else None
    except (TypeError, ValueError):
        return None


def _norm_timestamp(a):
    """Timestamp del SO si existe; si no, None (el caller puede poner now)."""
    for k in ("timestamp", "last_seen", "seen"):
        v = a.get(k)
        if v is None:
            continue
        try:
            t = int(v)
            # Android a veces usa microsegundos desde boot — si es enorme, no
            # lo tratamos como epoch; devolvemos el valor crudo solo si parece
            # epoch (s o ms).
            if t > 1e14:  # µs improbable como epoch
                return None
            if t > 1e12:  # ms → s
                return t // 1000
            return t
        except (TypeError, ValueError):
            continue
    return None


def legal_ap_view(ap):
    """Proyecta un AP enriquecido a solo campos legales para API/panel."""
    out = {}
    for k in LEGAL_FIELDS:
        if k in ap and ap[k] is not None:
            out[k] = ap[k]
    # alias estable para el panel
    if "encryption_raw" in ap and "capabilities" not in out:
        out["capabilities"] = ap.get("encryption_raw")
    return out


def _enrich_raw(a):
    """Una entrada cruda de scaninfo → dict enriquecido (interno)."""
    bssid = (a.get("bssid") or "").lower().strip()
    if not bssid:
        return None
    ssid = a.get("ssid")
    oculto = not ssid or not str(ssid).strip()
    caps = a.get("capabilities") or a.get("caps") or ""
    pc = parse_capabilities(caps)
    f = _norm_freq(a)
    bw = a.get("channel_bandwidth_mhz") or a.get("bandwidth")
    ts = _norm_timestamp(a)
    return {
        "bssid": bssid,
        "ssid": (ssid.strip() if isinstance(ssid, str) and ssid.strip() else None),
        "frequency_mhz": f,
        "channel": channel_of(f),
        "band": band_of(f),
        "channel_utilization": a.get("channel_utilization"),
        "dfs": bool(a.get("is_dfs") or a.get("dfs", False)),
        "rssi": _norm_rssi(a),
        "vendor": mac_vendor(bssid),
        "encryption": pc["encryption"],
        "cipher": pc["cipher"],
        "encryption_raw": caps or None,
        "capabilities": caps or None,
        "bandwidth": bw,
        "center_frequency": a.get("center_frequency_mhz") or a.get("center_frequency"),
        "hidden": 1 if oculto else 0,
        "timestamp": ts,
    }


def get_aps():
    """Lista de APs visibles con metadatos enriquecidos (legado monitor)."""
    data, err = _run(SCANINFO)
    if data is None:
        if err:
            log.debug("scaninfo: %s", err)
        return []
    if not isinstance(data, list):
        log.debug("scaninfo: esperado lista, got %s", type(data).__name__)
        return []
    logs = []
    seen = set()
    for a in data:
        if not isinstance(a, dict):
            continue
        ap = _enrich_raw(a)
        if not ap or ap["bssid"] in seen:
            continue
        seen.add(ap["bssid"])
        logs.append(ap)
    return logs


def scan_nearby(persist=False):
    """Escaneo bajo demanda de redes cercanas (solo campos legales).

    Returns dict:
      ok, networks, count, scanned_at, error, disclaimer, source
    """
    scanned_at = int(time.time())
    data, err = _run(SCANINFO)
    if data is None:
        return {
            "ok": False,
            "networks": [],
            "count": 0,
            "scanned_at": scanned_at,
            "error": err or "scan falló",
            "disclaimer": SCAN_DISCLAIMER,
            "source": "termux-wifi-scaninfo",
        }
    if not isinstance(data, list):
        return {
            "ok": False,
            "networks": [],
            "count": 0,
            "scanned_at": scanned_at,
            "error": "formato inesperado (no es lista)",
            "disclaimer": SCAN_DISCLAIMER,
            "source": "termux-wifi-scaninfo",
        }
    networks = []
    seen = set()
    for a in data:
        if not isinstance(a, dict):
            continue
        ap = _enrich_raw(a)
        if not ap or ap["bssid"] in seen:
            continue
        seen.add(ap["bssid"])
        if ap.get("timestamp") is None:
            ap["timestamp"] = scanned_at
        networks.append(legal_ap_view(ap))

    networks.sort(key=lambda n: (n.get("rssi") is None, -(n.get("rssi") or -999)))

    if persist and networks:
        try:
            # reusar track path parcial: upsert desde get_aps-equivalente
            con = db.connect()
            for ap in networks:
                full = dict(ap)
                full["encryption_raw"] = ap.get("capabilities")
                db.upsert_ap(
                    con, full,
                    encryption=ap.get("encryption"),
                    encryption_raw=ap.get("capabilities"),
                    bandwidth=ap.get("bandwidth"),
                    center_frequency=ap.get("center_frequency"),
                    hidden=ap.get("hidden"),
                )
                db.record_signal(con, ap["bssid"], ap.get("rssi"), ap.get("frequency_mhz"))
            db.log_run(con, "wifi",
                       rssi=max((n.get("rssi") or -100 for n in networks), default=None),
                       info=f"{len(networks)} aps (on-demand)")
            con.close()
        except Exception as e:
            log.warning("persist scan: %s", e)

    return {
        "ok": True,
        "networks": networks,
        "count": len(networks),
        "scanned_at": scanned_at,
        "error": None,
        "disclaimer": SCAN_DISCLAIMER,
        "source": "termux-wifi-scaninfo",
    }


def get_link():
    """Estado de la conexión actual (con qué AP estamos)."""
    d, err = _run(CONNINFO)
    if not d or not isinstance(d, dict) or not d.get("bssid"):
        if err:
            log.debug("conninfo: %s", err)
        return None
    state = d.get("supplicant_state") or d.get("state")
    return {
        "bssid": (d.get("bssid") or "").lower(),
        "ssid": d.get("ssid"),
        "ip": d.get("ip"),
        "link_speed_mbps": d.get("link_speed_mbps") or d.get("link_speed"),
        "network_id": d.get("network_id"),
        "rssi": _norm_rssi(d),
        "state": state,
        "hidden": d.get("ssid_hidden", False),
        "connected": state == "COMPLETED",
        "frequency_mhz": _norm_freq(d),
        "mac_address": d.get("mac_address"),
    }


def connection_status():
    """Estado de enlace enriquecido para panel/API (UX de conexión)."""
    checked_at = int(time.time())
    d, err = _run(CONNINFO)
    if d is None:
        return {
            "ok": False,
            "connected": False,
            "state": "UNKNOWN",
            "checked_at": checked_at,
            "error": err or "sin connectioninfo",
            "link": None,
            "quality": None,
            "hint": _hint_for_error(err),
        }
    if not isinstance(d, dict) or not d.get("bssid"):
        return {
            "ok": True,
            "connected": False,
            "state": (d or {}).get("supplicant_state") or "DISCONNECTED",
            "checked_at": checked_at,
            "error": None,
            "link": None,
            "quality": None,
            "hint": "Wi‑Fi no asociado. Conéctate a tu red en Ajustes de Android.",
        }
    state = d.get("supplicant_state") or d.get("state") or "UNKNOWN"
    connected = state == "COMPLETED"
    rssi = _norm_rssi(d)
    quality = _rssi_quality(rssi)
    link = {
        "bssid": (d.get("bssid") or "").lower(),
        "ssid": d.get("ssid"),
        "ip": d.get("ip"),
        "link_speed_mbps": d.get("link_speed_mbps") or d.get("link_speed"),
        "network_id": d.get("network_id"),
        "rssi": rssi,
        "state": state,
        "hidden": bool(d.get("ssid_hidden", False)),
        "connected": connected,
        "frequency_mhz": _norm_freq(d),
        "channel": channel_of(_norm_freq(d)),
        "band": band_of(_norm_freq(d)),
        "quality": quality,
    }
    hint = None
    if not connected:
        hint = f"Supplicant en {state}; esperando COMPLETED antes de escanear LAN."
    elif quality in ("débil", "muy débil"):
        hint = "Señal baja — el monitor puede fallar o ir lento."
    return {
        "ok": True,
        "connected": connected,
        "state": state,
        "checked_at": checked_at,
        "error": None,
        "link": link,
        "quality": quality,
        "hint": hint,
    }


def _rssi_quality(rssi):
    if rssi is None:
        return None
    if rssi >= -50:
        return "excelente"
    if rssi >= -60:
        return "buena"
    if rssi >= -70:
        return "aceptable"
    if rssi >= -80:
        return "débil"
    return "muy débil"


def _hint_for_error(err):
    if not err:
        return None
    e = err.lower()
    if "no encontrado" in e or "termux-api" in e:
        return "Instala Termux:API (`pkg install termux-api`) y la app Termux:API."
    if "permiso" in e or "vacía" in e or "empty" in e:
        return "Concede ubicación y Wi‑Fi cercanas a Termux:API (Android 6+/13+)."
    if "timeout" in e:
        return "La API Wi‑Fi no respondió a tiempo; reintenta."
    return None


def offline_backoff_seconds(failures, base=5, cap=60):
    """Backoff exponencial al perder Wi‑Fi: 5, 10, 20, 40, 60…"""
    try:
        n = max(0, int(failures))
    except (TypeError, ValueError):
        n = 0
    return min(cap, base * (2 ** min(n, 6)))


def track_once(known_routers=None):
    """Escanea y persiste; devuelve (aps, nuevos).

    Cada AP en `found` incluye `prev_encryption` (cifrado en DB antes del
    upsert) para que el monitor detecte downgrades en APs ya conocidos.
    """
    known_routers = known_routers or set()
    con = db.connect()
    found = get_aps()
    new = []
    for ap in found:
        prev = con.execute("SELECT * FROM aps WHERE bssid=?", (ap["bssid"],)).fetchone()
        ap["prev_encryption"] = (prev["encryption"] if prev else None)
        db.upsert_ap(
            con, ap,
            encryption=ap.get("encryption"),
            encryption_raw=ap.get("encryption_raw"),
            bandwidth=ap.get("bandwidth"),
            center_frequency=ap.get("center_frequency"),
            hidden=ap.get("hidden"),
        )
        # telemetría: una muestra histórica por AP por pasada
        db.record_signal(con, ap["bssid"], ap.get("rssi"), ap.get("frequency_mhz"))
        if prev is None:
            new.append(ap)
    # conexión actual -> station + network (memoria de routers)
    st = get_link()
    if st:
        db.record_station(con, st)
    db.log_run(con, "wifi",
               rssi=max([a.get("rssi") or -100 for a in found], default=None)
               if found else None,
               info=f"{len(found)} aps")
    con.close()
    return found, new


if __name__ == "__main__":
    aps, new = track_once()
    print(f"[wifi] {len(aps)} APs, {len(new)} nuevos")
    for a in aps[:6]:
        print(" ", a["ssid"] or "<oculto>", a["encryption"], a["channel"])
