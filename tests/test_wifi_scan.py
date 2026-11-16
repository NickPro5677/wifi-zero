# -*- coding: utf-8 -*-
"""Tests del escaneo Wi‑Fi legal (mock de termux-wifi-scaninfo / connectioninfo)."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from unittest import mock

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
sys.path.insert(0, os.path.join(BASE, "core"))
sys.path.insert(0, os.path.join(BASE, "scanner"))

import wifi_track  # noqa: E402


SAMPLE_SCAN = [
    {
        "bssid": "AA:BB:CC:11:22:33",
        "ssid": "Casa-WiFi",
        "frequency_mhz": 2412,
        "rssi": -42,
        "capabilities": "[WPA2-PSK-CCMP][RSN-PSK-CCMP][ESS]",
        "channel_bandwidth_mhz": 20,
        "timestamp": 1700000000,
    },
    {
        "bssid": "aa:bb:cc:44:55:66",
        "ssid": "",
        "frequency": 5180,
        "level": -67,
        "capabilities": "[RSN-SAE-CCMP][ESS]",
    },
    {
        "bssid": "11:22:33:44:55:66",
        "ssid": "Cafe-Guest",
        "frequency_mhz": 2462,
        "rssi": -78,
        "capabilities": "[ESS]",
    },
    # duplicado BSSID — debe ignorarse
    {
        "bssid": "AA:BB:CC:11:22:33",
        "ssid": "Casa-WiFi",
        "frequency_mhz": 2412,
        "rssi": -40,
        "capabilities": "[WPA2-PSK-CCMP][ESS]",
    },
]

SAMPLE_CONN = {
    "bssid": "AA:BB:CC:11:22:33",
    "ssid": "Casa-WiFi",
    "ip": "192.168.1.40",
    "link_speed_mbps": 144,
    "rssi": -45,
    "supplicant_state": "COMPLETED",
    "frequency_mhz": 2412,
    "ssid_hidden": False,
}


class _Proc:
    def __init__(self, stdout="", returncode=0, stderr=""):
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = stderr


class TestOfflineBackoff(unittest.TestCase):
    def test_backoff_curve(self):
        self.assertEqual(wifi_track.offline_backoff_seconds(0), 5)
        self.assertEqual(wifi_track.offline_backoff_seconds(1), 10)
        self.assertEqual(wifi_track.offline_backoff_seconds(2), 20)
        self.assertEqual(wifi_track.offline_backoff_seconds(3), 40)
        self.assertEqual(wifi_track.offline_backoff_seconds(4), 60)
        self.assertEqual(wifi_track.offline_backoff_seconds(99), 60)


class TestScanNearbyMock(unittest.TestCase):
    def test_scan_parses_legal_fields(self):
        with mock.patch("wifi_track.subprocess.run") as run:
            run.return_value = _Proc(json.dumps(SAMPLE_SCAN))
            out = wifi_track.scan_nearby(persist=False)
        self.assertTrue(out["ok"])
        self.assertEqual(out["count"], 3)  # sin duplicado
        self.assertIn("disclaimer", out)
        self.assertIn("Termux:API", out["disclaimer"])
        nets = out["networks"]
        # orden por RSSI desc
        self.assertEqual(nets[0]["ssid"], "Casa-WiFi")
        self.assertEqual(nets[0]["encryption"], "WPA2")
        self.assertEqual(nets[0]["channel"], 1)
        self.assertEqual(nets[0]["rssi"], -42)
        self.assertEqual(nets[0]["timestamp"], 1700000000)
        # hidden + WPA3 via SAE + frequency alias
        hidden = next(n for n in nets if n["bssid"] == "aa:bb:cc:44:55:66")
        self.assertEqual(hidden["encryption"], "WPA3")
        self.assertEqual(hidden["hidden"], 1)
        self.assertEqual(hidden["channel"], 36)
        self.assertEqual(hidden["rssi"], -67)
        self.assertNotIn("ssid", hidden)  # legal_ap_view omite None
        # OPEN
        open_ap = next(n for n in nets if n.get("ssid") == "Cafe-Guest")
        self.assertEqual(open_ap["encryption"], "OPEN")
        # solo campos legales
        for n in nets:
            for k in n:
                self.assertIn(k, wifi_track.LEGAL_FIELDS)

    def test_scan_missing_binary(self):
        with mock.patch("wifi_track.subprocess.run", side_effect=FileNotFoundError):
            out = wifi_track.scan_nearby()
        self.assertFalse(out["ok"])
        self.assertEqual(out["count"], 0)
        self.assertIn("termux-api", out["error"].lower())

    def test_scan_empty_response(self):
        with mock.patch("wifi_track.subprocess.run") as run:
            run.return_value = _Proc("")
            out = wifi_track.scan_nearby()
        self.assertFalse(out["ok"])
        self.assertIn("vacía", out["error"].lower())

    def test_scan_bad_json(self):
        with mock.patch("wifi_track.subprocess.run") as run:
            run.return_value = _Proc("not-json{")
            out = wifi_track.scan_nearby()
        self.assertFalse(out["ok"])

    def test_get_aps_uses_mock(self):
        with mock.patch("wifi_track.subprocess.run") as run:
            run.return_value = _Proc(json.dumps(SAMPLE_SCAN[:1]))
            aps = wifi_track.get_aps()
        self.assertEqual(len(aps), 1)
        self.assertEqual(aps[0]["ssid"], "Casa-WiFi")


class TestConnectionStatusMock(unittest.TestCase):
    def test_connected(self):
        with mock.patch("wifi_track.subprocess.run") as run:
            run.return_value = _Proc(json.dumps(SAMPLE_CONN))
            st = wifi_track.connection_status()
        self.assertTrue(st["ok"])
        self.assertTrue(st["connected"])
        self.assertEqual(st["state"], "COMPLETED")
        self.assertEqual(st["link"]["ssid"], "Casa-WiFi")
        self.assertEqual(st["link"]["ip"], "192.168.1.40")
        self.assertEqual(st["quality"], "excelente")

    def test_disconnected(self):
        with mock.patch("wifi_track.subprocess.run") as run:
            run.return_value = _Proc(json.dumps({"supplicant_state": "DISCONNECTED"}))
            st = wifi_track.connection_status()
        self.assertTrue(st["ok"])
        self.assertFalse(st["connected"])
        self.assertIsNone(st["link"])

    def test_get_link(self):
        with mock.patch("wifi_track.subprocess.run") as run:
            run.return_value = _Proc(json.dumps(SAMPLE_CONN))
            link = wifi_track.get_link()
        self.assertTrue(link["connected"])
        self.assertEqual(link["bssid"], "aa:bb:cc:11:22:33")


class TestLegalApView(unittest.TestCase):
    def test_strips_unknown(self):
        ap = {
            "ssid": "X",
            "bssid": "aa:bb:cc:dd:ee:ff",
            "rssi": -50,
            "encryption": "WPA2",
            "password": "should-never-appear",
            "handshake": "nope",
        }
        view = wifi_track.legal_ap_view(ap)
        self.assertNotIn("password", view)
        self.assertNotIn("handshake", view)
        self.assertEqual(view["ssid"], "X")


class TestScanPersist(unittest.TestCase):
    def test_persist_writes_db(self):
        import db
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "t.db")
        # forzar DB de prueba vía connect(db_path=…)
        with mock.patch("wifi_track.subprocess.run") as run:
            run.return_value = _Proc(json.dumps(SAMPLE_SCAN[:1]))
            # patch db.connect inside scan_nearby to use memory/temp
            real_connect = db.connect

            def _conn(*a, **k):
                return real_connect(db_path=path)

            with mock.patch("wifi_track.db.connect", side_effect=_conn):
                out = wifi_track.scan_nearby(persist=True)
        self.assertTrue(out["ok"])
        con = db.connect(db_path=path)
        rows = con.execute("SELECT bssid, ssid, encryption FROM aps").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ssid"], "Casa-WiFi")
        self.assertEqual(rows[0]["encryption"], "WPA2")
        con.close()


if __name__ == "__main__":
    unittest.main()
