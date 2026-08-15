# -*- coding: utf-8 -*-
"""Panel web de wifi-zero (F4): stdlib http, login (scrypt), SSE, gráficos.

Endpoints REST:
  GET  /login?to=...          -> página de login (si auth habilitada)
  POST /api/login             -> {user, pass} -> token de sesión
  GET  /api/stats             -> KPI
  GET  /api/hosts             -> hosts + ports + threat score
  GET  /api/hosts/<ip>        -> detalle de host (historia, puertos, eventos, riesgo)
  GET  /api/hosts/<ip>/risk   -> serie histórica de riesgo
  GET  /api/aps               -> APs (+ riesgo por AP, twin)
  GET  /api/aps/signals       -> muestras RSSI por AP
  GET  /api/networks          -> redes memorizadas
  GET  /api/events?since=N    -> feed de eventos
  GET  /api/topology          -> interfaces
  GET  /api/whitelist         -> whitelist
  POST /api/whitelist         -> añade entrada
  DELETE /api/whitelist?mac=  -> elimina entrada
  POST /api/scan              -> scan manual
  GET  /export/hosts.csv      -> export (CSV escapado)
  GET  /sse/events            -> flujo SSE de eventos (after every 3s)
  GET  /chart/signals.svg     -> gráfico SVG de señales
  GET  /chart/uptime.svg      -> gráfico SVG de uptime
  GET  /chart/risk.svg        -> gráfico SVG de riesgo histórico
Todo lo que no sea GET /login o /api/login requiere cabecera Authorization
si `panel.auth=true` (config). Los POST llevan protección CSRF (Origin) y el
login tiene throttling por IP (5 fallos / 10 min).
"""
import os
import sys
import json
import time
import base64
import threading
import queue
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "core"))
sys.path.insert(0, os.path.join(BASE_DIR, "scanner"))

import db  # noqa: E402
import config  # noqa: E402
import auth  # noqa: E402
import log  # noqa: E402
from threat import score_ap  # noqa: E402

log.setup("web", level=20)
LOGGER = log.get("web")

CFG = config.load()
PORT = int(os.environ.get("WZ_PORT", CFG.panel.get("port", 8788)))
BIND = CFG.panel.get("bind", "0.0.0.0")
PANEL = os.path.join(BASE_DIR, "panel")
PIDFILE = os.path.join(BASE_DIR, "logs", "server.pid")

# SSE broadcast (el monitor es otro proceso: se reinyecta desde SQLite)
_SUBSCRIBERS = set()
_SUB_LOCK = threading.Lock()
_SSE_LAST_ID = 0

STATIC_PUBLIC = {
    "/", "", "/login", "/login.html", "/host.html",
    "/app.js", "/style.css", "/favicon.svg", "/api/login",
}

MONITOR_PID = os.path.join(BASE_DIR, "logs", "monitor.pid")


def _broadcast(event, data):
    payload = f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"
    with _SUB_LOCK:
        dead = []
        for q in list(_SUBSCRIBERS):
            try:
                q.put_nowait(payload)
            except Exception:
                dead.append(q)
        for q in dead:
            _SUBSCRIBERS.discard(q)


def _notify_sse(rule, level, message, ip=None, mac=None):
    _broadcast("event", {"rule": rule, "level": level, "message": message, "ts": int(time.time())})


def _sse_pump():
    """Lee eventos nuevos de la DB y los emite a los clientes (proceso separado)."""
    global _SSE_LAST_ID
    try:
        con = db.connect()
        _SSE_LAST_ID = db.last_event_id(con)
        con.close()
    except Exception:
        _SSE_LAST_ID = 0
    while True:
        time.sleep(2)
        try:
            con = db.connect()
            evs = db.events_since(con, _SSE_LAST_ID, 80)
            con.close()
            for e in evs:
                _SSE_LAST_ID = max(_SSE_LAST_ID, int(e.get("id") or 0))
                _broadcast("event", e)
        except Exception:
            pass


def _pid_alive(path):
    try:
        pid = int(open(path).read().strip())
        os.kill(pid, 0)
        return pid
    except Exception:
        return None


def _health():
    charging, pct = True, None
    try:
        import json as _j
        bat = "/data/data/com.termux/files/usr/bin/termux-battery-status"
        out = __import__("subprocess").run([bat], capture_output=True, text=True, timeout=3)
        if out.returncode == 0 and out.stdout.strip():
            d = _j.loads(out.stdout)
            charging = d.get("status") == "CHARGING"
            pct = d.get("percentage")
    except Exception:
        pass
    con = db.connect()
    st = db.stats(con)
    last_st = None
    try:
        rows = db.stations_recent(con, 1)
        last_st = rows[-1] if rows else None
    except Exception:
        last_st = None
    con.close()
    return {
        "ok": True,
        "monitor_pid": _pid_alive(MONITOR_PID),
        "server_pid": os.getpid(),
        "last_run": st.get("last_run"),
        "battery_pct": pct,
        "charging": charging,
        "station": last_st,
        "version": st.get("version"),
    }


# tecla de sesión compartida (mismo proceso)
SESSION_KEY = os.environ.get("WZ_SESSION_SECRET")


def _fmt(ts):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "—"


def _serve_json(self, obj, code=200):
    body = json.dumps(obj).encode()
    self.send_response(code)
    self.send_header("Content-Type", "application/json; charset=utf-8")
    self.send_header("Content-Length", str(len(body)))
    self.send_header("X-Content-Type-Options", "nosniff")
    self.send_header("X-Frame-Options", "DENY")
    self.send_header("Cache-Control", "no-store")
    self.end_headers()
    self.wfile.write(body)


def _serve_file(self, path, ctype, cache="no-store"):
    try:
        with open(path, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", cache)
        self.end_headers()
        self.wfile.write(data)
    except FileNotFoundError:
        _serve_json(self, {"error": "not found"}, 404)


def _read_token(self):
    h = self.headers.get("Authorization", "")
    if h.startswith("Bearer "):
        return h[7:]
    q = parse_qs(urlparse(self.path).query)
    return q.get("token", [None])[0]


def authorized(handler, user):
    tok = _read_token(handler)
    return bool(tok and auth.verify_token(tok, user))


def _send_sse(self, q):
    self.send_response(200)
    self.send_header("Content-Type", "text/event-stream")
    self.send_header("Cache-Control", "no-cache")
    self.send_header("Connection", "keep-alive")
    self.send_header("X-Accel-Buffering", "no")
    self.end_headers()
    try:
        self.wfile.write(b"retry: 3000\n\n")
        self.wfile.flush()
        while True:
            try:
                msg = q.get(timeout=3)
                self.wfile.write(msg.encode())
                self.wfile.flush()
            except queue.Empty:
                try:
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
                except Exception:
                    break
            except Exception:
                break
    finally:
        with _SUB_LOCK:
            _SUBSCRIBERS.discard(q)


# ------------------------------------------------------------------ data API
def svg_signal(con, bssid=None, w=760, h=180):
    pts = db.signal_trend(con, bssid)
    if not pts:
        return '<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d"><text x="10" y="20" fill="#555" font-size="12">sin datos</text></svg>' % (w, h)
    times = [p["ts"] for p in pts]
    rssis = [(p["rssi"] or -100) for p in pts]
    t0, t1 = min(times), max(times)
    span = max(1, t1 - t0)
    r0, r1 = min(rssis), max(rssis)
    rspan = max(1, r1 - r0)
    path = []
    for i, (x, y) in enumerate(zip([(t - t0) / span for t in times], rssis)):
        px = 10 + (x) * (w - 30)
        py = 150 - (y - r0) / rspan * (h - 45)
        path.append(f"{px:.1f},{py:.1f}")
    d = "M" + " L".join(path)
    # colores según fuerza
    color = "#e8c66a" if min(rssis) < -70 else "#7ab89f"
    labels = []
    for v in range(-30, -95, -15):
        if r1 <= v <= r0:
            py = 150 - (v - r0) / rspan * (h - 45)
            labels.append(f'<text x="{(w-22):.0f}" y="{py:.0f}" fill="#444" font-size="9">{v}</text>')
    return f"""
<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}">
  <polyline points="{path}" fill="none" stroke="{color}" stroke-width="1.5"/>
  {''.join(labels)}
</svg>"""


def svg_uptime(con, ip, w=760, h=60):
    pts = db.host_history(con, ip, minutes=120)
    if not pts:
        return '<svg xmlns="http://www.w3.org/2000/svg" width="{}" height="{}"><text x="10" y="20" fill="#555" font-size="12">sin historia</text></svg>'.format(w, h)
    times = [p["ts"] for p in pts]
    t0, t1 = min(times), max(times)
    span = max(1, t1 - t0)
    block = []
    for p in pts:
        x = 10 + (p["ts"] - t0) / span * (w - 30)
        y = 10 if p["state"] else 40
        block.append(f'<rect x="{x:.1f}" y="{y}" width="2.2" height="6" fill="{"#6fce9a" if p["state"] else "#e07a7a"}"/>')
    return '<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}">{blocks}</svg>'.format(w=w, h=h, blocks="".join(block))


def svg_risk(con, ip, w=760, h=120):
    """Serie histórica de riesgo de un host (tabla scores)."""
    pts = db.score_history(con, ip, minutes=43200)
    if not pts:
        return '<svg xmlns="http://www.w3.org/2000/svg" width="{}" height="{}"><text x="10" y="20" fill="#555" font-size="12">sin historial de riesgo</text></svg>'.format(w, h)
    times = [p["ts"] for p in pts]
    vals = [(p["score"] or 0) for p in pts]
    t0, t1 = min(times), max(times)
    span = max(1, t1 - t0)
    path = []
    for i, (x, y) in enumerate(zip([(t - t0) / span for t in times], vals)):
        px = 10 + x * (w - 30)
        py = h - 15 - (y / 100.0) * (h - 40)
        path.append(f"{px:.1f},{py:.1f}")
    d = "M" + " L".join(path)
    rated = [f'<rect x="{10 + (t - t0) / span * (w - 30):.1f}" y="{h - 14}" width="2" height="4" fill="#e8c66a"/>'
             for t, v in zip(times, vals) if v >= 30 and v < 60]
    crit = [f'<rect x="{10 + (t - t0) / span * (w - 30):.1f}" y="{h - 8}" width="2" height="4" fill="#ff7a7a"/>'
            for t, v in zip(times, vals) if v >= 60]
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}">
  <polyline points="{path}" fill="none" stroke="#e8c66a" stroke-width="1.5"/>
  {''.join(rated)}
  {''.join(crit)}
  <text x="{w - 80}" y="{h - 25}" fill="#444" font-size="9">0</text>
  <text x="{w - 80}" y="{h - 65}" fill="#444" font-size="9">60 crit</text>
</svg>"""


# ------------------------------------------------------------------ seguridad
_LOGIN_ATTEMPTS = {}
_LOGIN_LOCK = threading.Lock()


def _login_fails(ip):
    """Intentos fallidos recientes de una IP (ventana 10 min)."""
    with _LOGIN_LOCK:
        cnt, ts = _LOGIN_ATTEMPTS.get(ip, (0, 0))
        if time.time() - ts > 600:
            return 0
        return cnt


def _login_fail(ip):
    with _LOGIN_LOCK:
        cnt, ts = _LOGIN_ATTEMPTS.get(ip, (0, time.time()))
        _LOGIN_ATTEMPTS[ip] = (cnt + 1, ts or time.time())


def _csrf_ok(handler):
    """Rechaza POST cross-site: si viene Origin/Referer, debe ser el propio panel."""
    if not Handler.auth_on:
        return True
    host = (handler.headers.get("Host") or "").split(":")[0]
    for hdr in ("Origin", "Referer"):
        v = (handler.headers.get(hdr) or "").strip()
        if v:
            import urllib.parse
            ref_host = urllib.parse.urlparse(v).hostname or ""
            if ref_host and ref_host != host:
                return False
    return True


# ------------------------------------------------------------------ handler
class Handler(BaseHTTPRequestHandler):
    server_version = "wifi-zero/3.1"
    auth_on = CFG.panel.get("auth", True)
    user = CFG.panel.get("user", "admin")

    # ------------ utils
    def _require(self):
        """True si la petición debe pasar (unauthorized → False)."""
        if not self.auth_on:
            return True
        p = urlparse(self.path).path
        if p in STATIC_PUBLIC:
            return True
        # escaneo local (start_all.sh) sin token
        if p == "/api/scan" and self.command == "POST":
            ip = (self.client_address or [""])[0]
            if ip in ("127.0.0.1", "::1"):
                return True
        return bool(authorized(self, self.user))

    def _json(self, obj, code=200):
        _serve_json(self, obj, code)

    def _file(self, path, ctype):
        _serve_file(self, path, ctype)

    # ---------------- routes
    def _api_route(self):
        con = db.connect()
        path = urlparse(self.path).path
        qs = parse_qs(urlparse(self.path).query)
        try:
            if path == "/api/stats":
                self._json(db.stats(con))
            elif path == "/api/health":
                self._json(_health())
            elif path == "/api/dashboard":
                self._json(_dashboard(con))
            elif path == "/api/hosts":
                self._json(db.hosts_with_threat(con, CFG, None))
            elif path.startswith("/api/hosts/"):
                rest = path.split("/")[3:]
                ip = rest[0]
                if len(rest) > 1 and rest[1] == "risk":
                    self._json({"risk": db.score_history(con, ip)})
                else:
                    self._json(sv_hosts_detail(con, ip))
            elif path == "/api/aps":
                aps = db.all_aps(con)
                dup_ssids = _twin_ssids(aps)
                for a in aps:
                    sc = score_ap(a, twin=(a.get("ssid") in dup_ssids), cfg=CFG)
                    a["risk"] = sc["score"]
                    a["tier"] = sc["tier"]
                self._json({"aps": aps, "networks": db.networks(con),
                            "stations": db.stations_recent(con)})
            elif path == "/api/aps/signals":
                bssid = qs.get("bssid", [None])[0]
                self._json({"signals": db.signal_trend(con, bssid)})
            elif path == "/api/whitelist":
                self._json({"whitelist": db.whitelist(con)})
            elif path == "/api/events":
                since = 0
                try: since = int(qs.get("since", ["0"])[0])
                except ValueError: pass
                self._json({"events": db.events_since(con, since, 300)})
            elif path == "/api/topology":
                self._json(self._topology())
            else:
                self._json({"error": "not found"}, 404)
        finally:
            con.close()

    def _topology(self):
        try:
            import lan_scan
            ifs = lan_scan.list_interfaces()
            return [{"iface": n, "ip": d["ip"], "prefix": d["prefix"]} for n, d in ifs.items()]
        except Exception as e:
            return {"error": str(e)}

    def do_GET(self):
        path = urlparse(self.path).path
        if not self._require():
            self._send401()
            return
        if path in ("/", ""):
            self._file(os.path.join(PANEL, "index.html"), "text/html; charset=utf-8")
        elif path in ("/login", "/login.html"):
            self._file(os.path.join(PANEL, "login.html"), "text/html; charset=utf-8")
        elif path == "/app.js":
            _serve_file(self, os.path.join(PANEL, "app.js"),
                        "text/javascript; charset=utf-8", "public, max-age=60")
        elif path == "/style.css":
            _serve_file(self, os.path.join(PANEL, "style.css"),
                        "text/css; charset=utf-8", "public, max-age=60")
        elif path == "/favicon.svg":
            _serve_file(self, os.path.join(PANEL, "favicon.svg"),
                        "image/svg+xml", "public, max-age=86400")
        elif path == "/host.html":
            self._file(os.path.join(PANEL, "host.html"), "text/html; charset=utf-8")
        elif path == "/sse/events":
            with _SUB_LOCK:
                q = queue.Queue()
                _SUBSCRIBERS.add(q)
            _send_sse(self, q)
        elif path.startswith("/api/"):
            self._api_route()
        elif path == "/export/hosts.csv":
            self._export_csv()
        elif path.startswith("/chart/signals.svg"):
            self._chart_signal()
        elif path.startswith("/chart/uptime.svg"):
            self._chart_uptime()
        elif path.startswith("/chart/risk.svg"):
            self._chart_risk()
        else:
            self._json({"error": "not found"}, 404)

    def _send401(self):
        self._json({"error": "no autorizado", "login": "/login"}, 401)

    def _export_csv(self):
        con = db.connect()
        hosts = db.hosts_with_threat(con, CFG, None)
        q = lambda v: '"' + str(v or "").replace('"', '""') + '"'
        lines = ["ip;mac;vendor;hostname;os;state;score;tier;first_seen;last_seen;ports"]
        for h in hosts:
            ports = ";".join(f"{p['port']}/{p['service'] or '?'}" for p in h["ports"])
            lines.append(";".join(map(q, [
                h["ip"], h.get("mac"), h.get("vendor"), h.get("hostname"), h.get("os"),
                h["state"], h["score"], h["tier"],
                _fmt(h["first_seen"]), _fmt(h["last_seen"]), ports])))
        body = ("\n".join(lines)).encode("utf-8-sig")
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", 'attachment; filename="hosts.csv"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        con.close()

    def _chart_signal(self):
        q = parse_qs(urlparse(self.path).query)
        bssid = q.get("bssid", [None])[0]
        con = db.connect()
        body = svg_signal(con, bssid).encode()
        con.close()
        self.send_response(200)
        self.send_header("Content-Type", "image/svg+xml")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _chart_uptime(self):
        q = parse_qs(urlparse(self.path).query)
        ip = q.get("ip", [""])[0]
        con = db.connect()
        body = svg_uptime(con, ip).encode()
        con.close()
        self.send_response(200)
        self.send_header("Content-Type", "image/svg+xml")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _chart_risk(self):
        q = parse_qs(urlparse(self.path).query)
        ip = q.get("ip", [""])[0]
        con = db.connect()
        body = svg_risk(con, ip).encode()
        con.close()
        self.send_response(200)
        self.send_header("Content-Type", "image/svg+xml")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        path = urlparse(self.path).path
        if not self._require():
            self._send401()
            return
        if not _csrf_ok(self):
            self._json({"error": "origen no permitido (CSRF)"}, 403)
            return
        if path == "/api/login":
            try:
                length = int(self.headers.get("Content-Length", 0))
                data = json.loads(self.rfile.read(length))
            except Exception as e:
                self._json({"error": str(e)}, 400)
                return
            client = (self.client_address[0] if self.client_address else "?")
            if _login_fails(client) >= 5:
                self._json({"error": "demasiados intentos, espera 10 min"}, 429)
                return
            if data.get("user") == self.user and verify(data.get("password", "")):
                tok = auth.create_token(self.user)
                self._json({"token": tok, "user": self.user})
            else:
                _login_fail(client)
                self._json({"error": "credenciales inválidas"}, 401)
        elif path == "/api/scan":
            _trigger_scan()
            self._json({"ok": True, "msg": "escaneo lanzado"})
        elif path == "/api/whitelist":
            self._whitelist_post()
        else:
            self._json({"error": "not found"}, 404)

    def do_DELETE(self):
        path = urlparse(self.path).path
        if not self._require():
            self._send401()
            return
        if not _csrf_ok(self):
            self._json({"error": "origen no permitido (CSRF)"}, 403)
            return
        if path == "/api/whitelist":
            q = parse_qs(urlparse(self.path).query)
            mac = (q.get("mac", [""])[0] or "").lower()
            if not mac:
                self._json({"error": "mac requerido"}, 400)
                return
            con = db.connect()
            con.execute("DELETE FROM whitelist WHERE mac=?", (mac,))
            con.commit()
            con.close()
            self._json({"ok": True})
        else:
            self._json({"error": "not found"}, 404)

    def _whitelist_post(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(length))
        except Exception:
            self._json({"error": "bad json"}, 400)
            return
        mac = (data.get("mac") or "").lower()
        if not mac:
            self._json({"error": "mac requerido"}, 400)
            return
        con = db.connect()
        db.add_whitelist(con, mac, data.get("label", "") or data.get("vendor", ""),
                         1 if data.get("trusted", True) else 0)
        self._json({"ok": True})
        con.close()

    def log_message(self, *a):
        pass


def verify(pw):
    stored = CFG.panel.get("password", "")
    return auth.verify_password(pw, stored) if stored else False


def _dashboard(con):
    """Un solo payload para el panel (menos round-trips)."""
    hosts = db.hosts_with_threat(con, CFG, None)
    aps = db.all_aps(con)
    dups = _twin_ssids(aps)
    for a in aps:
        sc = score_ap(a, twin=(a.get("ssid") in dups), cfg=CFG)
        a["risk"] = sc["score"]
        a["tier"] = sc["tier"]
        a["twin"] = bool(a.get("ssid") in dups)
    st = db.stats(con)
    crit = sum(1 for h in hosts if h.get("tier") == "crit")
    warn = sum(1 for h in hosts if h.get("tier") == "warn")
    return {
        "stats": {**st, "crit_hosts": crit, "warn_hosts": warn},
        "hosts": hosts,
        "aps": aps,
        "networks": db.networks(con),
        "stations": db.stations_recent(con, 8),
        "whitelist": db.whitelist(con),
        "events": db.events_since(con, 0, 80),
        "health": _health(),
    }


def _twin_ssids(aps):
    """SSIDs que aparecen con varias BSSIDs (posible evil-twin)."""
    seen, dups = set(), set()
    for a in aps:
        s = (a.get("ssid") or "").strip()
        if not s or s.startswith("<"):
            continue
        if s in seen:
            dups.add(s)
        seen.add(s)
    return dups


def sv_hosts_detail(con, ip):
    row = db.all_hosts(con)
    hit = next((x for x in row if x.get("ip") == ip), None)
    if not hit:
        return None
    hit["history"] = db.host_history(con, ip)
    hit["ports"] = db.all_ports(con, ip=ip)
    hit["risk"] = db.score_history(con, ip)
    hit["events"] = [e for e in db.all_events(con, 300) if e.get("ip") == ip]
    return hit


def _trigger_scan():
    def work():
        try:
            sys.path.insert(0, os.path.join(BASE_DIR, "core"))
            from monitor import Monitor
            Monitor(CFG).run()
        except Exception as e:
            db.add_event(db.connect(), "error", "warn", f"escaneo manual: {e}")
    threading.Thread(target=work, daemon=True).start()


def run():
    os.makedirs(os.path.dirname(PIDFILE), exist_ok=True)
    with open(PIDFILE, "w") as f:
        f.write(str(os.getpid()))
    threading.Thread(target=_sse_pump, name="sse-pump", daemon=True).start()
    srv = ThreadingHTTPServer((BIND, PORT), Handler)
    print(f"[server] pid {os.getpid()} → http://{BIND}:{PORT}  (auth={Handler.auth_on})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    run()