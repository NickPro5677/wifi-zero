# -*- coding: utf-8 -*-
"""wifi-zero web panel (F5) — pure stdlib HTTP server on port 8788.

Endpoints:
  GET  /                       -> panel/index.html
  GET  /api/stats              -> summary counts
  GET  /api/hosts              -> all hosts (+ appended open ports)
  GET  /api/aps                -> all visible APs
  GET  /api/events?since=N     -> events newer than N (polling feed)
  GET  /api/topology           -> network topology (interfaces)
  POST /api/scan               -> trigger a LAN+WiFi cycle now
  GET  /export/hosts.csv       -> hosts export
"""
import os
import sys
import json
import time
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "core"))
sys.path.insert(0, os.path.join(BASE_DIR, "scanner"))
import db  # noqa: E402

PORT = int(os.environ.get("WZ_PORT", "8788"))
PANEL_DIR = os.path.join(BASE_DIR, "panel")
PIDFILE = os.path.join(BASE_DIR, "logs", "server.pid")


def now_iso(ts):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "—"


def scan_iso(ts):
    return time.strftime("%H:%M:%S", time.localtime(ts)) if ts else "—"


def serve_hosts(con):
    hosts = db.all_hosts(con)
    ports = db.all_ports(con)
    byip = {}
    for p in ports:
        byip.setdefault(p["ip"], []).append({
            "port": p["port"], "proto": p["proto"], "service": p["service"],
            "product": p["product"], "version": p["version"],
        })
    out = []
    for h in hosts:
        d = dict(h)
        d["ports"] = byip.get(h["ip"], [])
        d["state_txt"] = "online" if h["state"] else "offline"
        d["first_seen"] = scan_iso(h["first_seen"])
        d["last_seen"] = scan_iso(h["last_seen"])
        out.append(d)
    return out


def topology():
    try:
        import lan_scan
        ifs = lan_scan.list_interfaces()
        return [{"iface": n, "ip": d["ip"], "prefix": d["prefix"]} for n, d in ifs.items()]
    except Exception as e:
        return {"error": str(e)}


def scan_background():
    def work():
        try:
            from monitor import run_cycle
            run_cycle(first=False)
            con = db.connect()
            db.log_run(con, "manual")
            con.close()
        except Exception as e:
            con = db.connect()
            db.add_event(con, "error", "warn", f"Escaneo manual falló: {e}")
            con.close()
    threading.Thread(target=work, daemon=True).start()


class Handler(BaseHTTPRequestHandler):
    server_version = "wifi-zero/0.1"

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path, ctype):
        try:
            with open(path, "rb") as f:
                data = f.read()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except FileNotFoundError:
            self._json({"error": "not found"}, 404)

    def do_GET(self):
        con = db.connect()
        path = self.path.split("?")[0]

        if path in ("/", "/index.html"):
            self._send_file(os.path.join(PANEL_DIR, "index.html"), "text/html; charset=utf-8")
        elif path == "/app.js":
            self._send_file(os.path.join(PANEL_DIR, "app.js"), "text/javascript; charset=utf-8")
        elif path == "/api/stats":
            self._json(db.stats(con))
        elif path == "/api/hosts":
            self._json(serve_hosts(con))
        elif path == "/api/aps":
            self._json({"aps": db.all_aps(con)})
        elif path == "/api/events":
            since = 0
            q = self.path.split("?", 1)[-1]
            if q.startswith("since="):
                try:
                    since = int(q[6:])
                except ValueError:
                    pass
            self._json({"events": db.events_since(con, since)})
        elif path == "/api/topology":
            self._json(topology())
        elif path == "/hosts.csv":
            self._csv(con)
        else:
            self._json({"error": "not found"}, 404)
        con.close()

    def _csv(self, con):
        hosts = serve_hosts(con)
        lines = ["ip;mac;vendor;hostname;os;state;first_seen;last_seen;ports"]
        for h in hosts:
            ports = ";".join(f"{p['port']}/{p['service'] or '?'}" for p in h["ports"])
            lines.append(f"{h['ip']};{h.get('mac') or ''};{h.get('hostname') or ''};"
                         f"{h.get('os') or ''};{h['state_txt']};{h['first_seen']};"
                         f"{h['last_seen']};{ports}")
        body = ("\n".join(lines)).encode("utf-8-sig")
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", 'attachment; filename="hosts.csv"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path == "/api/scan":
            scan_background()
            self._json({"ok": True, "msg": "Escaneo lanzado"})
        else:
            self._json({"error": "not found"}, 404)

    def log_message(self, *a):
        pass


def run():
    with open(PIDFILE, "w") as f:
        f.write(str(os.getpid()))
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[server] pid {os.getpid()} → http://0.0.0.0:{PORT}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    run()