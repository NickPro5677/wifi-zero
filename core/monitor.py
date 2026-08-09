# -*- coding: utf-8 -*-
"""wifi-zero monitor (F3): continuous loop that keeps "tracking absolutely everything".

Every cycle:
  - LAN scan (neigh + TCP)  -> hosts, ports
  - WiFi scan (API)         -> visible APs
  - diff against DB to emit EVENTS:
      new_host      (an IP/MAC appears that we've never seen)
      mac_change    (same IP now answers with a different MAC -> spoofing)
      offline       (a host that was state=1 is not seen for a while)
      new_ap        (a new router appears near us -> possible rogue AP)
      recon         (a service/port opened on an existing host)
  - fires termux-notification for level >= NOTIFY_LEVEL (default warn)
"""
import os
import subprocess
import sys
import time
import socket

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "core"))
sys.path.insert(0, os.path.join(BASE_DIR, "scanner"))
import db  # noqa: E402
import lan_scan  # noqa: E402
import wifi_track  # noqa: E402

# ------------------------------------------------------------------ config
CYCLE_LAN = int(os.environ.get("WZ_LAN_INTERVAL", "60"))
CYCLE_WIFI = int(os.environ.get("WZ_WIFI_INTERVAL", "120"))
NOTIFY_LEVELS = {"info": 0, "warn": 1, "crit": 2}
NOTIFY_MIN = NOTIFY_LEVELS.get(os.environ.get("WZ_NOTIFY_MIN", "warn"), 1)
PIDFILE = os.path.join(BASE_DIR, "logs", "monitor.pid")


def notify(title, msg):
    exe = "/data/data/com.termux/files/usr/bin/termux-notification"
    if os.path.exists(exe):
        try:
            subprocess.run([exe, "-t", title, "-c", msg, "--alert-once"],
                           timeout=5, check=False)
        except Exception:
            pass


def emit(con, kind, level, message, ip=None, mac=None):
    db.add_event(con, kind, level, message, ip=ip, mac=mac)
    print(f"[evt:{level}] {message}")
    if NOTIFY_LEVELS[level] >= NOTIFY_MIN:
        notify(f"wifi-zero · {level}", message)


# ------------------------------------------------------------------- diffs
def _hosts_before(con):
    return {h["ip"]: h for h in db.all_hosts(con)}


def diff_hosts(con, before, after):
    """after: {ip: {'mac':..}} -> emit new_host / mac_change / offline."""
    for ip, data in after.items():
        prev = before.get(ip)
        mac = data.get("mac")
        if prev is None:
            vend = lan_scan.mac_vendor(mac) if mac else None
            emit(con, "new_host", "warn",
                 f"Nuevo host en la red: {ip}" + (f" (MAC {mac}, {vend})" if mac else ""),
                 ip=ip, mac=mac)
        elif mac and prev.get("mac") and mac != prev.get("mac"):
            emit(con, "mac_change", "crit",
                 f"IP {ip} cambió de MAC {prev.get('mac')} -> {mac} (¿spoofing?)",
                 ip=ip, mac=mac)
    # offline: known up hosts not seen this cycle
    seen = set(after.keys())
    for ip, h in before.items():
        if h.get("state") == 1 and ip not in seen:
            emit(con, "offline", "info", f"Host sin señales: {ip}", ip=ip)


def diff_aps(con, before, new_aps):
    for ap in new_aps:
        if ap.get("ssid", "").strip() == "" or ap.get("ssid", "").startswith("<"):
            continue
        emit(con, "new_ap", "warn",
             f"AP nuevo visible: {ap.get('ssid')} (BSSID {ap.get('bssid')}, "
             f"canal {ap.get('channel')}, RSSI {ap.get('rssi')})",
             ip=None, mac=ap.get("bssid"))


def diff_ports(con, before_ports, ip, new_ports):
    old = {p["port"] for p in before_ports if p.get("ip") == ip}
    for p in new_ports:
        if p not in old:
            emit(con, "recon", "warn", f"Puerto abierto nuevo en {ip}: {p}/tcp", ip=ip)


# ------------------------------------------------------------------- loop
def run_cycle(first=False):
    con = db.connect()
    before_hosts = _hosts_before(con)
    before_ports = db.all_ports(con)

    # LAN
    try:
        lan_scan.scan_once()
    except Exception as e:
        print("lan err", e)

    # rebuild "after" from DB (scan_once already persisted)
    cur_hosts = {h["ip"]: h for h in db.all_hosts(con)}
    after = {}
    for ip, h in cur_hosts.items():
        mac = h.get("mac")
        # only consider up hosts as present now
        if h.get("state") == 1:
            after[ip] = {"mac": mac}

    if not first:
        diff_hosts(con, before_hosts, after)

    # ports diff (new open port events)
    cur_ports = db.all_ports(con)
    opened = {}
    for p in cur_ports:
        ip, port = p["ip"], p["port"]
        if p["first_seen"] == p["last_seen"]:
            opened.setdefault(ip, []).append(port)
    if not first:
        for ip, ports in opened.items():
            diff_ports(con, before_ports, ip, ports)

    # WiFi
    before_aps = {a["bssid"] for a in db.all_aps(con)}
    try:
        _, new_aps = wifi_track.track_once()
        if not first:
            diff_aps(con, before_aps, new_aps)
    except Exception as e:
        print("wifi err", e)

    con.close()


def loop():
    with open(PIDFILE, "w") as f:
        f.write(str(os.getpid()))
    print(f"[monitor] pid {os.getpid()} — LAN cada {CYCLE_LAN}s, WiFi cada {CYCLE_WIFI}s")
    first = True
    next_lan = next_wifi = 0
    while True:
        t = time.time()
        try:
            if t >= next_lan:
                run_cycle(first=first)
                next_lan = t + CYCLE_LAN
            if t >= next_wifi:
                if not first:
                    try:
                        _, new = wifi_track.track_once()
                        before = {a["bssid"] for a in db.all_aps(db.connect())}
                        diff_aps(db.connect(), before, new)
                    except Exception as e:
                        print("wifi err", e)
                next_wifi = t + CYCLE_WIFI
        except KeyboardInterrupt:
            break
        except Exception as e:
            print("[monitor] err", e)
        first = False
        time.sleep(5)


def stop():
    if os.path.exists(PIDFILE):
        pid = open(PIDFILE).read().strip()
        try:
            os.kill(int(pid), 15)
            print(f"[monitor] stopped {pid}")
        except Exception:
            pass
        os.remove(PIDFILE)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "stop":
        stop()
    else:
        loop()