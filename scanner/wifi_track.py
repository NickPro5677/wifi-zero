# -*- coding: utf-8 -*-
"""Wi-Fi tracker F1 — lee la API de Android (Termux:API) y la amplía.

Extra:
  - parseo de `capabilities` -> cifrado (WPA2/WPA3/OPEN), cipher, flags
  - SSID oculto (conexión informa ssid_hidden / scaninfo devuelve ssid vacío)
  - bandwidth y center_frequency de la banda
  - estado del enlace actual (`termux-wifi-connectioninfo`): link_speed, red
  - registro de señales históricas y de stations en la DB
"""
import os
import subprocess
import sys
import json
import logging

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "core"))
sys.path.insert(0, os.path.join(BASE_DIR, "scanner"))
import db  # noqa: E402
from lan_scan import mac_vendor  # noqa: E402

log = logging.getLogger("wifi")

SCANINFO = "/data/data/com.termux/files/usr/bin/termux-wifi-scaninfo"
CONNINFO = "/data/data/com.termux/files/usr/bin/termux-wifi-connectioninfo"


def _run(exe, timeout=15):
    try:
        out = subprocess.run([exe], capture_output=True, text=True, timeout=timeout)
        if out.returncode == 0 and out.stdout.strip():
            return json.loads(out.stdout)
    except Exception as e:
        log.debug("error %s: %s", exe, e)
    return None


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


def get_aps():
    """Lista de APs visibles con metadatos enriquecidos."""
    data = _run(SCANINFO) or []
    logs = []
    seen = set()
    for a in data:
        bssid = (a.get("bssid") or "").lower()
        if not bssid or bssid in seen:
            continue
        seen.add(bssid)
        oculto = not a.get("ssid") or not a.get("ssid").strip()
        pc = parse_capabilities(a.get("capabilities"))
        f = a.get("frequency_mhz")
        bw = a.get("channel_bandwidth_mhz")
        logs.append({
            "bssid": bssid,
            "ssid": a.get("ssid") or None,
            "frequency_mhz": f,
            "channel": channel_of(f),
            "band": band_of(f),
            "channel_utilization": a.get("channel_utilization"),
            "dfs": a.get("is_dfs") or a.get("dfs", False),
            "rssi": a.get("rssi"),
            "vendor": mac_vendor(bssid),
            "encryption": pc["encryption"],
            "cipher": pc["cipher"],
            "encryption_raw": a.get("capabilities"),
            "bandwidth": bw,
            "center_frequency": a.get("center_frequency_mhz"),
            "hidden": 1 if oculto else 0,
        })
    return logs


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


def get_link():
    """Estado de la conexión actual (con qué AP estamos)."""
    d = _run(CONNINFO) or {}
    if not d or not d.get("bssid"):
        return None
    return {
        "bssid": (d.get("bssid") or "").lower(),
        "ssid": d.get("ssid"),
        "ip": d.get("ip"),
        "link_speed_mbps": d.get("link_speed_mbps"),
        "network_id": d.get("network_id"),
        "rssi": d.get("rssi"),
        "state": d.get("supplicant_state"),
        "hidden": d.get("ssid_hidden", False),
        "connected": d.get("supplicant_state") == "COMPLETED",
        "frequency_mhz": d.get("frequency_mhz"),
    }


def track_once(known_routers=None):
    """Escanea y persiste; devuelve (aps, nuevos)."""
    known_routers = known_routers or set()
    con = db.connect()
    found = get_aps()
    new = []
    for ap in found:
        prev = con.execute("SELECT * FROM aps WHERE bssid=?", (ap["bssid"],)).fetchone()
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