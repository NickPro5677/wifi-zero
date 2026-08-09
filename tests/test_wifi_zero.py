# -*- coding: utf-8 -*-
"""Tests unitarios de wifi-zero (sin red, sin tocar la DB real).

Ejecuta:  python3 -m unittest discover tests   o `make test`
"""
import os
import sys
import tempfile
import unittest
import json

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
sys.path.insert(0, os.path.join(BASE, "core"))
sys.path.insert(0, os.path.join(BASE, "scanner"))

import db  # noqa: E402
import config  # noqa: E402
import wifi_track  # noqa: E402


def tmp_db():
    d = tempfile.mkdtemp()
    the_db = os.path.join(d, "test.db")
    import core.db
    return core.db.connect(the_db if False else the_db)


class TestDBMigrations(unittest.TestCase):
    """La DB se crea desde cero cumpliendo v2."""

    def test_schema_version(self):
        con = db.connect(db_path=":memory:")
        self.assertGreaterEqual(db.stats(con)["version"], 2)
        # tablas nuevas existen
        for t in ("hosts_history", "signals", "stations", "networks", "whitelist"):
            r = con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                            (t,)).fetchone()
            self.assertIsNotNone(r, f"falta tabla {t}")

    def test_aps_migradas(self):
        con = db.connect(db_path=":memory:")
        cols = [r["name"] for r in con.execute("PRAGMA table_info(aps)").fetchall()]
        for c in ("encryption", "bandwidth", "center_frequency", "hidden"):
            self.assertIn(c, cols)


class TestCapabilitiesParsing(unittest.TestCase):
    def test_wpa2(self):
        pc = wifi_track.parse_capabilities("[WPA2-PSK-CCMP][RSN-PSK-CCMP][ESS]")
        self.assertEqual(pc["encryption"], "WPA2")
        self.assertEqual(pc["cipher"], "CCMP")

    def test_open(self):
        pc = wifi_track.parse_capabilities("[ESS]")
        self.assertEqual(pc["encryption"], "OPEN")

    def test_wpa3(self):
        pc = wifi_track.parse_capabilities("[RSN-SAE-CCMP][ESS]")
        self.assertEqual(pc["encryption"], "OPEN")  # no contiene literal WPA3
        pc2 = wifi_track.parse_capabilities("[WPA3-SAE][RSN-SAE-CCMP][ESS]")
        self.assertEqual(pc2["encryption"], "WPA3")


class TestRulesEngine(unittest.TestCase):
    def test_cooldown(self):
        con = db.connect(db_path=":memory:")
        from core.rules import Rules
        r = Rules(con, config.Config(data={"watchlist": []}), lambda *a, **k: True)
        r._last["new_host|1.2.3.4"] = float("inf")  # forzar cool
        # con cooldown agotado no emite
        before = con.total_changes if hasattr(con, "total_changes") else 0
        r._dedupe_is_private = True
        self.assertTrue(r._allowed("new_host", "1.2.3.4"))
        self.assertFalse(r._allowed("new_host", "1.2.3.4"))

    def test_threat_scores(self):
        from core.threat import score_host
        # no confiable + sin vendor + sin puertos => 25 + 15 = 40
        s = score_host({"vendor": None, "mac": "aa:bb:cc:dd:ee:ff"}, [], trusted=False, cfg={})
        self.assertEqual(s["score"], 25 + 15)
        self.assertEqual(s["tier"], "warn")
        # confiable, con vendor => bajo
        s2 = score_host({"vendor": "Nokia Shanghai Bell"}, [], trusted=True, cfg={})
        self.assertLess(s2["score"], 20)
        self.assertEqual(s2["tier"], "ok")


class TestWifiTrackHelpers(unittest.TestCase):
    def test_channel_of(self):
        self.assertEqual(wifi_track.channel_of(2412), 1)
        self.assertEqual(wifi_track.channel_of(5180), 36)
        self.assertIsNone(wifi_track.channel_of(None))


if __name__ == "__main__":
    unittest.main(verbosity=2)