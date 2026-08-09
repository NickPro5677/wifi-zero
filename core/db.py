# -*- coding: utf-8 -*-
"""SQLite persistence for wifi-zero.

SQLite is shared across the scanner, wifi tracker, monitor and web panel.
Tables: hosts, ports, aps, events, runs.
"""
import os
import sqlite3
import time

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "wifi.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    ip TEXT PRIMARY KEY,
    mac TEXT,
    vendor TEXT,
    hostname TEXT,
    os TEXT,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    state INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS ports (
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    proto TEXT DEFAULT 'tcp',
    service TEXT,
    product TEXT,
    version TEXT,
    first_seen INTEGER,
    last_seen INTEGER,
    PRIMARY KEY (ip, port, proto)
);
CREATE TABLE IF NOT EXISTS aps (
    bssid TEXT PRIMARY KEY,
    ssid TEXT,
    frequency_mhz INTEGER,
    rssi INTEGER,
    rssi_max INTEGER,
    vendor TEXT,
    first_seen INTEGER,
    last_seen INTEGER
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    kind TEXT NOT NULL,
    level TEXT NOT NULL,
    message TEXT NOT NULL,
    ip TEXT,
    mac TEXT
);
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    kind TEXT NOT NULL,
    host_count INTEGER DEFAULT 0,
    rssi INTEGER,
    info TEXT
);
"""


def connect():
    os.makedirs(DATA_DIR, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    con.commit()
    return con


def now():
    return int(time.time())


def add_event(con, kind, level, message, ip=None, mac=None):
    con.execute(
        "INSERT INTO events(ts, kind, level, message, ip, mac) VALUES (?,?,?,?,?,?)",
        (now(), kind, level, message, ip, mac),
    )
    con.commit()


def last_event_id(con):
    row = con.execute("SELECT COALESCE(MAX(id),0) AS m FROM events").fetchone()
    return row["m"]


def events_since(con, since=0, limit=200):
    rows = con.execute(
        "SELECT * FROM events WHERE id > ? ORDER BY id DESC LIMIT ?", (since, limit)
    ).fetchall()
    return [dict(r) for r in reversed(rows)]


def all_events(con, limit=300):
    rows = con.execute(
        "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in reversed(rows)]


def upsert_host(con, ip, mac=None, vendor=None, hostname=None, osn=None, state=1):
    t = now()
    row = con.execute("SELECT * FROM hosts WHERE ip=?", (ip,)).fetchone()
    if row:
        con.execute(
            """UPDATE hosts SET mac=COALESCE(?,mac), vendor=COALESCE(?,vendor),
               hostname=COALESCE(?,hostname), os=COALESCE(?,os),
               last_seen=?, state=? WHERE ip=?""",
            (mac, vendor, hostname, osn, t, state, ip),
        )
    else:
        con.execute(
            """INSERT INTO hosts(ip,mac,vendor,hostname,os,first_seen,last_seen,state)
               VALUES (?,?,?,?,?,?,?,?)""",
            (ip, mac, vendor, hostname, osn, t, t, state),
        )
    con.commit()


def touch_host(con, ip):
    row = con.execute("SELECT ip FROM hosts WHERE ip=?", (ip,)).fetchone()
    if row:
        con.execute("UPDATE hosts SET last_seen=?, state=1 WHERE ip=?", (now(), ip))
        con.commit()


def all_hosts(con):
    rows = con.execute("SELECT * FROM hosts ORDER BY ip").fetchall()
    return [dict(r) for r in rows]


def upsert_port(con, ip, port, proto="tcp", service=None, product=None, version=None):
    t = now()
    row = con.execute(
        "SELECT * FROM ports WHERE ip=? AND port=? AND proto=?",
        (ip, port, proto),
    ).fetchone()
    if row:
        con.execute(
            """UPDATE ports SET service=COALESCE(?,service), product=COALESCE(?,product),
               version=COALESCE(?,version), last_seen=? WHERE ip=? AND port=? AND proto=?""",
            (service, product, version, t, ip, port, proto),
        )
    else:
        con.execute(
            """INSERT OR IGNORE INTO ports(ip,port,proto,service,product,version,first_seen,last_seen)
               VALUES (?,?,?,?,?,?,?,?)""",
            (ip, port, proto, service, product, version, t, t),
        )
    con.commit()


def all_ports(con, ip=None):
    q = "SELECT * FROM ports"
    args = ()
    if ip:
        q += " WHERE ip=?"
        args = (ip,)
    rows = con.execute(q + " ORDER BY ip, port", args).fetchall()
    return [dict(r) for r in rows]


def upsert_ap(con, ap):
    t = now()
    bssid = ap.get("bssid", "").lower()
    if not bssid:
        return
    rssi = ap.get("rssi")
    row = con.execute("SELECT * FROM aps WHERE bssid=?", (bssid,)).fetchone()
    if row:
        best = max(row["rssi_max"] or (rssi or 0), rssi or 0)
        con.execute(
            """UPDATE aps SET ssid=COALESCE(?,ssid), frequency_mhz=COALESCE(?,frequency_mhz),
               rssi=?, rssi_max=?, vendor=COALESCE(?,vendor), last_seen=? WHERE bssid=?""",
            (ap.get("ssid"), ap.get("frequency_mhz"), rssi, best, ap.get("vendor"), t, bssid),
        )
    else:
        con.execute(
            """INSERT INTO aps(bssid,ssid,frequency_mhz,rssi,rssi_max,vendor,first_seen,last_seen)
               VALUES (?,?,?,?,?,?,?,?)""",
            (bssid, ap.get("ssid"), ap.get("frequency_mhz"), rssi, rssi or 0,
             ap.get("vendor"), t, t),
        )
    con.commit()


def all_aps(con):
    rows = con.execute("SELECT * FROM aps ORDER BY COALESCE(rssi,0) DESC").fetchall()
    return [dict(r) for r in rows]


def log_run(con, kind, host_count=0, rssi=None, info=""):
    cur = con.execute(
        "INSERT INTO runs(ts,kind,host_count,rssi,info) VALUES (?,?,?,?,?)",
        (now(), kind, host_count, rssi, info),
    )
    con.commit()
    return cur.lastrowid


def stats(con):
    hosts = con.execute("SELECT COUNT(*) AS c FROM hosts").fetchone()["c"]
    up = con.execute("SELECT COUNT(*) AS c FROM hosts WHERE state=1").fetchone()["c"]
    aps = con.execute("SELECT COUNT(*) AS c FROM aps").fetchone()["c"]
    ev = con.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]
    port_ips = con.execute("SELECT COUNT(DISTINCT ip) AS c FROM ports").fetchone()["c"]
    first = con.execute("SELECT MIN(first_seen) AS m FROM hosts").fetchone()["m"]
    last = con.execute("SELECT MAX(ts) AS m FROM runs").fetchone()["m"]
    return {
        "hosts": hosts, "up": up, "aps": aps, "events": ev,
        "port_ips": port_ips, "first_scan": first, "last_run": last,
    }