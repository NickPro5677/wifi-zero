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
from core.rules import Rules  # noqa: E402


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
        self.assertEqual(pc["encryption"], "WPA3")  # SAE = WPA3-Personal
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
        # no confiable + sin vendor + sin hostname => 25 + 15 + 5 = 45
        s = score_host({"vendor": None, "mac": "dc:a6:32:5c:01:02"}, [], trusted=False, cfg={})
        self.assertEqual(s["score"], 25 + 15 + 5)
        self.assertEqual(s["tier"], "warn")
        # confiable, con vendor => bajo
        s2 = score_host({"vendor": "Nokia Shanghai Bell"}, [], trusted=True, cfg={})
        self.assertLess(s2["score"], 20)
        self.assertEqual(s2["tier"], "ok")

    def test_weights_from_config_object(self):
        from core.threat import score_host
        cfg = config.Config(data={"threat": {"weights": {"untrusted": 40, "no_vendor": 0}}})
        s = score_host({"vendor": "X", "mac": "dc:a6:32:5c:01:02"}, [], trusted=False, cfg=cfg)
        self.assertEqual(s["score"], 40)


class TestWifiTrackHelpers(unittest.TestCase):
    def test_channel_of(self):
        self.assertEqual(wifi_track.channel_of(2412), 1)
        self.assertEqual(wifi_track.channel_of(5180), 36)
        self.assertEqual(wifi_track.channel_of(5995), 9)  # 6GHz
        self.assertIsNone(wifi_track.channel_of(None))

    def test_band_of(self):
        self.assertEqual(wifi_track.band_of(2412), "2.4GHz")
        self.assertEqual(wifi_track.band_of(5200), "5GHz")
        self.assertEqual(wifi_track.band_of(6000), "6GHz")
        self.assertIsNone(wifi_track.band_of(None))


class TestThreatV3(unittest.TestCase):
    def test_randomized_mac(self):
        from core.threat import is_randomized_mac, score_host, score_ap
        # '02:' primer byte = 0x02 → bit LAA a 1
        self.assertTrue(is_randomized_mac("02:00:00:00:00:01"))
        self.assertFalse(is_randomized_mac("dc:a6:32:5c:01:02"))
        self.assertFalse(is_randomized_mac(""))

    def test_dangerous_ports_score(self):
        from core.threat import score_host
        base = {"vendor": "Nokia", "mac": "dc:a6:32:5c:01:02"}
        s0 = score_host(base, [], trusted=True, cfg={})
        s1 = score_host(base, [{"port": 23, "service": "telnet"}], trusted=True, cfg={})
        self.assertGreater(s1["score"], s0["score"])
        self.assertGreaterEqual(s1["score"], 10)  # weak_svc

    def test_score_ap(self):
        from core.threat import score_ap
        open = score_ap({"encryption": "OPEN", "rssi": -55}, twin=False, cfg={})
        secure = score_ap({"encryption": "WPA3", "rssi": -55}, twin=False, cfg={})
        self.assertGreater(open["score"], secure["score"])
        self.assertEqual(secure["tier"], "ok")


class TestUpsertAp(unittest.TestCase):
    def test_new_ap_insert(self):
        con = db.connect(db_path=":memory:")
        db.upsert_ap(con, {"bssid": "aa:bb:cc:dd:ee:ff", "ssid": "Hogar",
                           "frequency_mhz": 2412, "rssi": -55, "vendor": "X"},
                     encryption="WPA2")
        aps = db.all_aps(con)
        self.assertEqual(len(aps), 1)
        self.assertEqual(aps[0]["bssid"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(aps[0]["encryption"], "WPA2")
        db.upsert_ap(con, {"bssid": "aa:bb:cc:dd:ee:ff", "ssid": "Hogar",
                           "frequency_mhz": 2412, "rssi": -60, "vendor": "X"},
                     encryption="WPA2")
        self.assertEqual(db.all_aps(con)[0]["rssi"], -60)
        self.assertEqual(db.all_aps(con)[0]["rssi_max"], -55)


class TestRulesV3(unittest.TestCase):
    def _rules(self):
        con = db.connect(db_path=":memory:")
        return con, Rules(con, config.Config(data={"watchlist": []}), lambda *a, **k: True)

    def test_gateway_changed(self):
        con, r = self._rules()
        fired = []
        r.emit = lambda rule, level, msg, ip=None, mac=None: (fired.append((rule, level)), True)[1]
        r.gateway_changed("aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb", "192.168.1.1")
        self.assertEqual(fired[0][0], "gateway_changed")
        self.assertEqual(fired[0][1], "crit")

    def test_ip_conflict(self):
        con, r = self._rules()
        fired = []
        r.emit = lambda rule, level, msg, ip=None, mac=None: (fired.append((rule, level)), True)[1]
        r.ip_conflict("192.168.1.50", ["aa:1", "bb:2"])
        self.assertEqual(fired[0][0], "ip_conflict")
        r.ip_conflict("192.168.1.50", ["aa:1", "bb:2"])  # cooldown
        self.assertEqual(len(fired), 1)

    def test_mac_randomized(self):
        con, r = self._rules()
        fired = []
        r.emit = lambda rule, level, msg, ip=None, mac=None: (fired.append((rule, level)), True)[1]
        r.mac_randomized("192.168.1.60", "02:00:00:00:00:01")
        self.assertEqual(fired[0][0], "mac_randomized")

    def test_ap_open(self):
        con, r = self._rules()
        fired = []
        r.emit = lambda rule, level, msg, ip=None, mac=None: (fired.append((rule, level)), True)[1]
        r.ap_new({"bssid": "cc:cc:cc:cc:cc:cc", "ssid": "VECINO", "channel": 6,
                  "rssi": -60, "encryption": "OPEN"})
        rules_fired = {f[0] for f in fired}
        self.assertIn("ap_open", rules_fired)
        self.assertIn("new_ap", rules_fired)


class TestRecordScoresBatch(unittest.TestCase):
    def test_batch(self):
        con = db.connect(db_path=":memory:")
        db.record_scores(con, [
            {"ip": "1.1.1.1", "score": 10, "tier": "ok"},
            {"ip": "2.2.2.2", "score": 70, "tier": "crit"},
        ])
        self.assertEqual(con.execute("SELECT COUNT(*) AS c FROM scores").fetchone()["c"], 2)


class TestPrune(unittest.TestCase):
    def test_prune_removes_old(self):
        con = db.connect(db_path=":memory:")
        con.execute("INSERT INTO signals(ts,bssid,rssi,frequency_mhz) VALUES (?,?,?,?)",
                    (db.now() - 86400 * 60, "aa:bb:cc:dd:ee:ff", -55, 2412))
        con.commit()
        db.prune(con, {"signals": 7})
        self.assertEqual(con.execute("SELECT COUNT(*) AS c FROM signals").fetchone()["c"], 0)


class TestOfflineTransition(unittest.TestCase):
    def test_host_state_transition(self):
        """Un host con state=1 y no visible en el ciclo → offline (regla)."""
        con = db.connect(db_path=":memory:")
        db.upsert_host(con, "192.168.1.10", mac="aa:bb:cc:dd:ee:ff", state=1)
        live_now = {"192.168.1.20"}
        from core.rules import Rules
        fired = []
        r = Rules(con, config.Config(data={"watchlist": []}),
                  lambda rule, level, msg, ip=None, mac=None: (fired.append((rule, msg)), True)[1])
        before = {h["ip"]: h for h in db.all_hosts(con)}
        for ip, h in before.items():
            if h.get("state") == 1 and ip not in live_now:
                r.host_offline(ip, h.get("mac"))
        self.assertEqual(fired[0][0], "offline")


if __name__ == "__main__":
    unittest.main(verbosity=2)