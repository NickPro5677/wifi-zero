# -*- coding: utf-8 -*-
"""Wi-Fi tracker for wifi-zero (F4).

Reads the Android WiFi scan API (`termux-wifi-scaninfo`, part of Termux:API)
and stores every visible AP. No monitor mode / deauth possible without root;
this is the passive wide view Android gives us: every neighbouring router we
can hear, their channel, signal and vendors (by BSSID OUI).

The API binary must exist:  `pkg install termux-api`
"""
import os
import subprocess
import sys
import time
import json

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "core"))
sys.path.insert(0, os.path.join(BASE_DIR, "scanner"))
import db  # noqa: E402
from lan_scan import mac_vendor  # noqa: E402

SCANINFO = "/data/data/com.termux/files/usr/bin/termux-wifi-scaninfo"


def channel_of(freq):
    if not freq:
        return None
    if 2412 <= freq <= 2484:
        return (freq - 2412) // 5 + 1
    if 5180 <= freq <= 5825:
        return (freq - 5180) // 5 + 36
    return freq


def get_aps():
    """Return the list of visible access points."""
    out = subprocess.run([SCANINFO], capture_output=True, text=True, timeout=20)
    if out.returncode != 0 or not out.stdout.strip():
        return []
    data = json.loads(out.stdout)
    aps = []
    for a in data:
        bssid = a.get("bssid")
        if not bssid:
            continue
        freq = a.get("frequency_mhz")
        aps.append({
            "bssid": bssid.lower(),
            "ssid": a.get("ssid") or "<oculto>",
            "frequency_mhz": freq,
            "channel": channel_mhz(freq),
            "rssi": a.get("rssi"),
            "vendor": mac_vendor(bssid),
        })
    return aps


def channel_mhz(f):
    if f and 2412 <= f <= 2484:
        return (f - 2412) // 5 + 1
    if f and 5180 <= f <= 5825:
        return (f - 5180) // 5 + 36
    return None


def track_once(known_routers=None):
    """Scan APs, persist, return (aps, new_aps)."""
    known_routers = known_routers or set()
    con = db.connect()
    found = get_aps()
    new = []
    for ap in found:
        prev = con.execute("SELECT * FROM aps WHERE bssid=?", (ap["bssid"],)).fetchone()
        db.upsert_ap(con, ap)
        if prev is None:
            new.append(ap)
    db.log_run(con, "wifi", rssi=max([a.get("rssi") or -100 for a in found], default=None)
               if found else None, info=f"{len(found)} aps")
    con.close()
    return found, new


if __name__ == "__main__":
    aps, new = track_once()
    print(f"[wifi] {len(aps)} APs visibles, {len(new)} nuevos")
    for a in aps[:6]:
        print(f"  {a['ssid'] or '<-->'}")