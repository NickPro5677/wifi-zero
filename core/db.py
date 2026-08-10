# -*- coding: utf-8 -*-
"""Persistencia SQLite de wifi-zero (compartida por escáner, monitor y panel).

Usa migraciones versionadas: cada lista dentro de MIGRATIONS sube la
`schema_version`. No alteres migraciones ya publicadas: añade una nueva.
"""
import os
import sqlite3
import time

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "wifi.db")

# v1: esquema original entregado en el v0
# v2: amplía aps (encryption, bandwidth, hidden) y añade redes/whitelist/history
MIGRATIONS = [
    # -- v1 (original) ------------------------------------------------
    """
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
    """,
    # v2 (mejoras de datos "F1"") ----------------------------------------
    """
    ALTER TABLE aps ADD COLUMN encryption TEXT;
    ALTER TABLE aps ADD COLUMN encryption_raw TEXT;
    ALTER TABLE aps ADD COLUMN bandwidth TEXT;
    ALTER TABLE aps ADD COLUMN center_frequency INTEGER;
    ALTER TABLE aps ADD COLUMN hidden INTEGER DEFAULT 0;
    CREATE TABLE IF NOT EXISTS hosts_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER NOT NULL,
        ip TEXT NOT NULL,
        state INTEGER DEFAULT 1,
        mac TEXT,
        vendor TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_hosts_history_ts ON hosts_history(ts);
    CREATE TABLE IF NOT EXISTS signals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER NOT NULL,
        bssid TEXT NOT NULL,
        rssi INTEGER,
        frequency_mhz INTEGER,
        link_speed INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_signals_ts ON signals(ts);
    CREATE TABLE IF NOT EXISTS stations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER NOT NULL,
        bssid TEXT,
        ssid TEXT,
        ip TEXT,
        link_speed_mbps INTEGER,
        network_id INTEGER,
        rssi INTEGER,
        state TEXT,
        connected INTEGER DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS networks (
        bssid TEXT PRIMARY KEY,
        ssid TEXT,
        network_id INTEGER,
        last_seen INTEGER,
        count INTEGER DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS whitelist (
        mac TEXT PRIMARY KEY,
        label TEXT,
        trusted INTEGER DEFAULT 1,
        added INTEGER NOT NULL
    );
    """,
    # v3 (v3: riesgo histórico, índices y limpieza) --------------------------
    """
    CREATE TABLE IF NOT EXISTS scores (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER NOT NULL,
        ip TEXT NOT NULL,
        score INTEGER NOT NULL,
        tier TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_scores_ip_ts ON scores(ip, ts);
    CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
    CREATE INDEX IF NOT EXISTS idx_ports_last_seen ON ports(last_seen);
    CREATE INDEX IF NOT EXISTS idx_stations_ts ON stations(ts);
    """,
]


def _apply_schema(con, idx):
    """Ejecuta la migración `idx` y la registra en `migrations`."""
    con.executescript(MIGRATIONS[idx])
    con.execute("INSERT OR REPLACE INTO migrations(version, applied_at) VALUES (?, ?)",
                (idx + 1, now()))
    con.commit()


def connect(db_path=DB_PATH):
    os.makedirs(DATA_DIR, exist_ok=True)
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA busy_timeout=5000")
    con.executescript(
        "CREATE TABLE IF NOT EXISTS migrations (version INTEGER PRIMARY KEY, applied_at INTEGER);"
    )
    cur = con.execute("SELECT COALESCE(MAX(version),0) AS v FROM migrations").fetchone()
    current = cur["v"]
    for idx in range(current, len(MIGRATIONS)):
        _apply_schema(con, idx)
    con.commit()
    return con


def now():
    return int(time.time())


# -------------------------------------------------------------- events
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


# -------------------------------------------------------------- hosts
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
        _record_history(con, ip, state)
    else:
        con.execute(
            """INSERT INTO hosts(ip,mac,vendor,hostname,os,first_seen,last_seen,state)
               VALUES (?,?,?,?,?,?,?,?)""",
            (ip, mac, vendor, hostname, osn, t, t, state),
        )
        _record_history(con, ip, state)
    con.commit()


def _record_history(con, ip, state):
    """Registra un punto de presencia para los gráficos de uptime."""
    t = now()
    # compacto: una fila por día para no crecer sin límite
    con.execute(
        """INSERT INTO hosts_history(ts, ip, state) SELECT ?,?,? WHERE NOT EXISTS (
               SELECT 1 FROM hosts_history WHERE ip=? AND state=?
                   AND ts >= ?)""",
        (t, ip, state, ip, state, t - 600),
    )


def record_signal(con, bssid, rssi, mhz, link_speed=None, station=False):
    con.execute(
        "INSERT INTO signals(ts,bssid,rssi,frequency_mhz,link_speed) VALUES (?,?,?,?,?)",
        (now(), bssid, rssi, mhz, link_speed),
    )
    con.commit()


def record_station(con, st):
    t = now()
    ip = st.get("ip")
    bssid = (st.get("bssid") or "").lower()
    con.execute(
        """INSERT INTO stations(ts,bssid,ssid,ip,link_speed_mbps,network_id,rssi,connected)
           VALUES (?,?,?,?,?,?,?,?)""",
        (t, bssid, st.get("ssid"), ip, st.get("link_speed_mbps"), st.get("network_id"),
         st.get("rssi"), 1 if st.get("connected", True) else 0),
    )
    con.execute(
        """INSERT OR IGNORE INTO networks(bssid,ssid,network_id,last_seen,count)
           VALUES (?,?,?,?,1)""",
        (bssid, st.get("ssid"), st.get("network_id"), t),
    )


def whitelist(con):
    rows = con.execute("SELECT * FROM whitelist").fetchall()
    return [dict(r) for r in rows]


def is_trusted_mac(con, mac):
    if not mac:
        return None
    row = con.execute("SELECT trusted FROM whitelist WHERE mac=?", (mac.lower(),)).fetchone()
    return bool(row["trusted"]) if row else None


def add_whitelist(con, mac, label="", trusted=1):
    con.execute(
        "INSERT OR REPLACE INTO whitelist(mac,label,trusted,added) VALUES (?,?,?,?)",
        (mac.lower(), label, trusted, now()),
    )
    con.commit()


def all_hosts(con):
    rows = con.execute("SELECT * FROM hosts ORDER BY ip").fetchall()
    return [dict(r) for r in rows]


# -------------------------------------------------------------- ports
def upsert_port(con, ip, port, proto="tcp", service=None, product=None, version=None):
    t = now()
    row = con.execute(
        "SELECT * FROM ports WHERE ip=? AND port=? AND proto=?", (ip, port, proto)
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


# -------------------------------------------------------------- aps
def upsert_ap(con, ap, encryption=None, encryption_raw=None, bandwidth=None,
              center_frequency=None, hidden=False):
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
               rssi=?, rssi_max=?, vendor=COALESCE(?,vendor), encryption=COALESCE(?,encryption),
               encryption_raw=COALESCE(?,encryption_raw), bandwidth=COALESCE(?,bandwidth),
               center_frequency=COALESCE(?,center_frequency),
               hidden=COALESCE(?,hidden), last_seen=? WHERE bssid=?""",
            (ap.get("ssid"), ap.get("frequency_mhz"), rssi, best, ap.get("vendor"),
             encryption, encryption_raw, ap.get("bandwidth"), center_frequency,
             1 if hidden else None, t, bssid),
        )
    else:
        con.execute(
            """INSERT INTO aps(bssid,ssid,frequency_mhz,rssi,rssi_max,vendor,
               encryption,encryption_raw,bandwidth,center_frequency,hidden,first_seen,last_seen)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (bssid, ap.get("ssid"), ap.get("frequency_mhz"), rssi, rssi or 0,
             ap.get("vendor"), encryption, encryption_raw, ap.get("bandwidth"),
             center_frequency, 1 if hidden else 0, t, t),
        )
    con.commit()


def all_aps(con):
    rows = con.execute("SELECT * FROM aps ORDER BY COALESCE(rssi,0) DESC").fetchall()
    return [dict(r) for r in rows]


def aps_since(con, since_ts=None):
    q = "SELECT * FROM aps"
    if since_ts:
        q += " WHERE last_seen >= ?"
        rows = con.execute(q, (since_ts,)).fetchall()
    else:
        rows = con.execute(q).fetchall()
    return [dict(r) for r in rows]


# -------------------------------------------------------------- runs/stats
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
    version = con.execute("SELECT COALESCE(MAX(version),0) AS v FROM migrations").fetchone()["v"]
    return {
        "hosts": hosts, "up": up, "aps": aps, "events": ev,
        "port_ips": port_ips, "first_scan": first, "last_run": last,
        "version": version,
    }


# ------------------------------------------------------------------ panel data
def host_history(con, ip, minutes=120):
    """Puntos de presencia de un host (para curva de uptime)."""
    since = now() - minutes * 60
    rows = con.execute(
        """SELECT ts, state FROM hosts_history WHERE ip=? AND ts>=?
           ORDER BY ts""", (ip, since),
    ).fetchall()
    return [dict(r) for r in rows]


def signal_trend(con, bssid=None, minutes=120):
    """Muestras RSSI/host para AP. Devuelve (bssid, ts, rssi)."""
    since = now() - minutes * 60
    if bssid:
        rows = con.execute(
            "SELECT ts,rssi FROM signals WHERE bssid=? AND ts>=? ORDER BY ts",
            (bssid, since)).fetchall()
    else:
        rows = con.execute(
            "SELECT bssid,ts,rssi FROM signals WHERE ts>=? ORDER BY ts", (since,)).fetchall()
    return [dict(r) for r in rows]


def networks(con):
    rows = con.execute("SELECT * FROM networks ORDER BY count DESC").fetchall()
    return [dict(r) for r in rows]


def stations_recent(con, limit=20):
    rows = con.execute("SELECT * FROM stations ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in reversed(rows)]


def hosts_with_threat(con, cfg=None, ports=None):
    """Hosts + score + whitelist. Devuelve list[dict]."""
    from threat import score_host
    hosts = all_hosts(con)
    pl = (ports or all_ports(con))
    by_mac = {wh["mac"]: wh for wh in whitelist(con)}
    out = []
    for h in hosts:
        tm = by_mac.get((h.get("mac") or "").lower())
        trusted = bool(tm["trusted"]) if tm else None
        hp = [p for p in pl if p.get("ip") == h["ip"]]
        sc = score_host(h, hp, trusted, cfg)
        out.append({**h, "trusted": trusted, "label": (tm or {}).get("label", ""),
                    "score": sc["score"], "tier": sc["tier"], "ports": hp})
    out.sort(key=lambda x: (-x["score"], x["ip"]))
    return out


# ------------------------------------------------------------------ riesgo histórico
def record_score(con, ip, score, tier):
    """Persiste un punto de la serie de riesgo de un host (para /chart/risk)."""
    con.execute("INSERT INTO scores(ts,ip,score,tier) VALUES (?,?,?,?)",
                (now(), ip, int(score), tier))
    con.commit()


def score_history(con, ip=None, minutes=1440):
    since = now() - minutes * 60
    if ip:
        rows = con.execute(
            "SELECT ts,score,tier FROM scores WHERE ip=? AND ts>=? ORDER BY ts",
            (ip, since)).fetchall()
    else:
        rows = con.execute(
            "SELECT ts,ip,score,tier FROM scores WHERE ts>=? ORDER BY ts",
            (since,)).fetchall()
    return [dict(r) for r in rows]


# ------------------------------------------------------------------ limpieza por retención
DEFAULT_RETENTION_DAYS = {
    "signals": 7, "hosts_history": 14, "scores": 30,
    "stations": 7, "events": 30, "ports_closed": 7,
}


def prune(con, retention_days=None):
    """Borra filas viejas según retención en días. Devuelve dict con filas por tabla."""
    cfg = retention_days or DEFAULT_RETENTION_DAYS
    cutoff = now() - 86400 * max(1, int(cfg.get("events", 30)))
    removed = {}

    def cut(table, ts_col, days):
        c = cutoff if days == cfg.get("events") else now() - 86400 * max(1, int(days))
        cur = con.execute(f"DELETE FROM {table} WHERE {ts_col} < ?", (c,))
        return cur.rowcount

    for table, ts_col in (("signals", "ts"), ("hosts_history", "ts"),
                          ("stations", "ts"), ("scores", "ts"), ("events", "ts")):
        removed[table] = cut(table, ts_col, cfg.get(table, 30))
    # puertos sin ver en N días (servicio cerrado) se olvidan
    closed_days = max(1, int(cfg.get("ports_closed", 7)))
    removed["ports"] = con.execute(
        "DELETE FROM ports WHERE last_seen < ?", (now() - 86400 * closed_days,)).rowcount
    con.commit()
    return removed