# -*- coding: utf-8 -*-
"""Tests HTTP del plano de control v4 (setup, auth, CSRF, redact, control).

Sin red externa: ThreadingHTTPServer en 127.0.0.1 efímero + config/DB temporales.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock
from urllib.error import HTTPError
from urllib.request import Request, urlopen

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
sys.path.insert(0, os.path.join(BASE, "core"))
sys.path.insert(0, os.path.join(BASE, "scanner"))

import auth  # noqa: E402
import config  # noqa: E402
import db  # noqa: E402
import server  # noqa: E402
from core.supervisor import Supervisor  # noqa: E402


def _http(method, url, body=None, headers=None, timeout=8):
    data = None if body is None else json.dumps(body).encode()
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    req = Request(url, data=data, headers=hdrs, method=method)
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode()
            return resp.status, json.loads(raw) if raw else {}
    except HTTPError as e:
        raw = e.read().decode()
        try:
            payload = json.loads(raw) if raw else {}
        except Exception:
            payload = {"raw": raw}
        return e.code, payload


class _FakeHeaders(dict):
    def get(self, k, default=None):
        for key, val in self.items():
            if key.lower() == k.lower():
                return val
        return default


class _FakeHandler:
    def __init__(self, host="127.0.0.1:8788", origin=None, referer=None):
        h = _FakeHeaders({"Host": host})
        if origin is not None:
            h["Origin"] = origin
        if referer is not None:
            h["Referer"] = referer
        self.headers = h


class ControlPlaneHarness:
    """Servidor efímero con config/DB aisladas."""

    def __init__(self, password=None, user="admin", bind_cfg="127.0.0.1"):
        self.tmpdir = tempfile.mkdtemp(prefix="wz-http-")
        os.makedirs(os.path.join(self.tmpdir, "data"), exist_ok=True)
        os.makedirs(os.path.join(self.tmpdir, "logs"), exist_ok=True)
        self.cfg_path = os.path.join(self.tmpdir, "config.json")
        self.db_path = os.path.join(self.tmpdir, "data", "wifi.db")
        data = {
            "panel": {
                "port": 0,
                "bind": bind_cfg,
                "auth": True,
                "user": user,
                "password": auth.hash_password(password) if password else "",
            },
            "pushes": {"telegram_token": "TELEGRAM-SECRET-TOKEN", "enabled": False},
        }
        cfg = config.Config(data=data, path=self.cfg_path)
        cfg.save()
        con = db.connect(db_path=self.db_path)
        con.close()

        self._patches = [
            mock.patch.object(config, "CONFIG_PATH", self.cfg_path),
            mock.patch.object(server, "CFG", config.load(self.cfg_path)),
            mock.patch.object(db, "DB_PATH", self.db_path),
            mock.patch.object(db, "DATA_DIR", os.path.join(self.tmpdir, "data")),
        ]
        for p in self._patches:
            p.start()

        self.sup = Supervisor()
        self.sup.cfg = config.load(self.cfg_path)
        server.attach_supervisor(self.sup)
        ThreadingHTTPServer.allow_reuse_address = True
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        self.port = self.httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()
        self._wait_ready()

    def _wait_ready(self, attempts=40):
        for _ in range(attempts):
            try:
                code, _ = _http("GET", self.url("/api/setup/status"), timeout=1)
                if code == 200:
                    return
            except Exception:
                pass
            time.sleep(0.05)
        raise RuntimeError("panel de test no respondió a tiempo")

    def stop(self):
        try:
            self.sup._stop_evt.set()
            t = self.sup._mon_thread
            if t and t.is_alive():
                t.join(timeout=2)
            self.sup._mon_thread = None
            self.sup._monitor = None
        except Exception:
            pass
        try:
            self.httpd.shutdown()
            self.httpd.server_close()
        except Exception:
            pass
        if self._thread.is_alive():
            self._thread.join(timeout=2)
        for p in reversed(self._patches):
            p.stop()
        server._SUPERVISOR = None

    def url(self, path):
        return self.base + path


class TestCsrfUnit(unittest.TestCase):
    """CSRF sin HTTP (determinista)."""

    def test_csrf_ok_same_host(self):
        prev = server.Handler.auth_on
        server.Handler.auth_on = True
        try:
            h = _FakeHandler(host="127.0.0.1:8788", origin="http://127.0.0.1:8788")
            self.assertTrue(server._csrf_ok(h))
            h2 = _FakeHandler(host="127.0.0.1:8788",
                              referer="http://127.0.0.1:8788/panel")
            self.assertTrue(server._csrf_ok(h2))
        finally:
            server.Handler.auth_on = prev

    def test_csrf_rejects_foreign_origin(self):
        prev = server.Handler.auth_on
        server.Handler.auth_on = True
        try:
            h = _FakeHandler(host="127.0.0.1:8788", origin="http://evil.example")
            self.assertFalse(server._csrf_ok(h))
        finally:
            server.Handler.auth_on = prev

    def test_csrf_skipped_when_auth_off(self):
        prev = server.Handler.auth_on
        server.Handler.auth_on = False
        try:
            h = _FakeHandler(host="127.0.0.1:8788", origin="http://evil.example")
            self.assertTrue(server._csrf_ok(h))
        finally:
            server.Handler.auth_on = prev


class TestSetupAndAuth(unittest.TestCase):
    def tearDown(self):
        if getattr(self, "h", None):
            self.h.stop()

    def test_setup_status_public(self):
        self.h = ControlPlaneHarness(password=None)
        code, body = _http("GET", self.h.url("/api/setup/status"))
        self.assertEqual(code, 200)
        self.assertTrue(body["setup_needed"])

    def test_setup_creates_session(self):
        self.h = ControlPlaneHarness(password=None)
        code, body = _http(
            "POST", self.h.url("/api/setup"),
            {"user": "admin", "password": "secreto123", "bind": "127.0.0.1",
             "start_monitor": False},
            headers={"Origin": self.h.base},
        )
        self.assertEqual(code, 200, body)
        self.assertTrue(body.get("ok"))
        self.assertIn("token", body)
        # tras setup, /api/setup exige Bearer; con token → 400 "ya configurado"
        code2, body2 = _http(
            "POST", self.h.url("/api/setup"),
            {"user": "admin", "password": "otraclave", "bind": "127.0.0.1"},
            headers={
                "Origin": self.h.base,
                "Authorization": f"Bearer {body['token']}",
            },
        )
        self.assertEqual(code2, 400, body2)
        self.assertIn("configurado", body2.get("error", ""))

    def test_protected_routes_need_bearer(self):
        self.h = ControlPlaneHarness(password="secreto123")
        for path in ("/api/config", "/api/control/status"):
            code, body = _http("GET", self.h.url(path))
            self.assertEqual(code, 401, path)
        code, _ = _http("POST", self.h.url("/api/control/start"),
                        {}, headers={"Origin": self.h.base})
        self.assertEqual(code, 401)


class TestRedactAndControl(unittest.TestCase):
    def setUp(self):
        self.h = ControlPlaneHarness(password="secreto123")
        code, body = _http(
            "POST", self.h.url("/api/login"),
            {"user": "admin", "password": "secreto123"},
            headers={"Origin": self.h.base},
        )
        self.assertEqual(code, 200, body)
        self.token = body["token"]
        self.auth = {"Authorization": f"Bearer {self.token}", "Origin": self.h.base}

    def tearDown(self):
        self.h.stop()

    def test_config_redacts_secrets(self):
        code, body = _http("GET", self.h.url("/api/config"), headers=self.auth)
        self.assertEqual(code, 200)
        cfg = body["config"]
        self.assertEqual(cfg["panel"]["password"], "")
        self.assertTrue(cfg["panel"]["password_set"])
        self.assertEqual(cfg["pushes"]["telegram_token"], "***")
        self.assertTrue(cfg["pushes"]["telegram_token_set"])
        dumped = json.dumps(cfg)
        self.assertNotIn("TELEGRAM-SECRET-TOKEN", dumped)

    def test_csrf_http_rejects_foreign_origin(self):
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Origin": "http://evil.example",
        }
        code, body = _http("POST", self.h.url("/api/backup"), {}, headers=headers)
        self.assertEqual(code, 403, body)
        self.assertIn("CSRF", body.get("error", ""))

    def test_control_status(self):
        code, body = _http("GET", self.h.url("/api/control/status"), headers=self.auth)
        self.assertEqual(code, 200)
        self.assertIn("mode", body)
        self.assertIn("setup_needed", body)
        self.assertFalse(body["setup_needed"])

    def test_control_start_and_status(self):
        with mock.patch("monitor.Monitor") as Mon:
            inst = mock.MagicMock()
            inst.mode = "running"
            inst.manual_pause = False
            Mon.return_value = inst

            def fake_loop():
                while not self.h.sup._stop_evt.wait(0.05):
                    pass

            inst.loop.side_effect = fake_loop
            code, body = _http(
                "POST", self.h.url("/api/control/start"), {},
                headers=self.auth,
            )
            self.assertEqual(code, 200, body)
            self.assertTrue(body.get("ok"))
            time.sleep(0.15)
            code_st, st = _http(
                "GET", self.h.url("/api/control/status"), headers=self.auth,
            )
            self.assertEqual(code_st, 200, st)
            self.assertTrue(st.get("monitor_thread") or st.get("monitor_running"))
            self.h.sup._stop_evt.set()
            t = self.h.sup._mon_thread
            if t:
                t.join(timeout=2)


class TestBackupWalSafe(unittest.TestCase):
    def test_backup_is_openable_sqlite(self):
        import checks
        import sqlite3
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, "data"))
        path = os.path.join(d, "data", "wifi.db")
        con = db.connect(db_path=path)
        db.upsert_host(con, "192.168.1.50", mac="aa:bb:cc:dd:ee:ff", state=1)
        con.close()
        with mock.patch.object(checks, "BASE_DIR", d):
            r = checks.make_backup()
        self.assertTrue(r["ok"], r)
        bak = sqlite3.connect(r["path"])
        try:
            n = bak.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
            self.assertEqual(n, 1)
        finally:
            bak.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
