# -*- coding: utf-8 -*-
"""Tests de core.runtime y soft-fail del escaneo Wi‑Fi opcional."""
from __future__ import annotations

import os
import sys
import unittest
from unittest import mock

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
sys.path.insert(0, os.path.join(BASE, "core"))
sys.path.insert(0, os.path.join(BASE, "scanner"))

import runtime  # noqa: E402
import wifi_track  # noqa: E402


class TestRuntimeDetection(unittest.TestCase):
    def setUp(self):
        runtime.clear_cache()
        self._env = os.environ.get("WZ_RUNTIME")

    def tearDown(self):
        if self._env is None:
            os.environ.pop("WZ_RUNTIME", None)
        else:
            os.environ["WZ_RUNTIME"] = self._env
        runtime.clear_cache()

    def test_force_linux(self):
        os.environ["WZ_RUNTIME"] = "linux"
        runtime.clear_cache()
        self.assertTrue(runtime.is_linux_host())
        self.assertFalse(runtime.is_termux())
        self.assertEqual(runtime.recommended_bind(), "0.0.0.0")
        profile = runtime.host_profile()
        self.assertEqual(profile["runtime"], "linux")
        self.assertTrue(profile["wifi_nearby_optional"])
        self.assertTrue(any("Pi" in h or "LAN" in h for h in profile["hints"]))

    def test_force_termux(self):
        os.environ["WZ_RUNTIME"] = "termux"
        runtime.clear_cache()
        self.assertTrue(runtime.is_termux())
        self.assertFalse(runtime.is_linux_host())
        self.assertEqual(runtime.recommended_bind(), "127.0.0.1")

    def test_ip_cmd_resolves(self):
        os.environ["WZ_RUNTIME"] = "linux"
        runtime.clear_cache()
        cmd = runtime.ip_cmd()
        self.assertTrue(cmd)
        # en CI Linux debería existir iproute2 o al menos el nombre
        self.assertIn("ip", os.path.basename(cmd))


class TestOptionalWifiScan(unittest.TestCase):
    def setUp(self):
        runtime.clear_cache()
        self._env = os.environ.get("WZ_RUNTIME")
        os.environ["WZ_RUNTIME"] = "linux"
        runtime.clear_cache()

    def tearDown(self):
        if self._env is None:
            os.environ.pop("WZ_SESSION_SECRET", None)
            os.environ.pop("WZ_RUNTIME", None)
        else:
            os.environ["WZ_RUNTIME"] = self._env
        runtime.clear_cache()

    def test_missing_tool_message_linux(self):
        err = wifi_track._missing_tool_error("termux-wifi-scaninfo")
        self.assertIn("opcional", err.lower())
        self.assertIn("lan", err.lower())

    def test_scan_nearby_soft_fail_linux(self):
        with mock.patch("wifi_track.subprocess.run", side_effect=FileNotFoundError):
            out = wifi_track.scan_nearby()
        self.assertFalse(out["ok"])
        self.assertEqual(out["count"], 0)
        self.assertTrue(out.get("optional"))
        self.assertTrue(
            "opcional" in (out["error"] or "").lower()
            or "termux" in (out["error"] or "").lower()
            or "no encontrado" in (out["error"] or "").lower()
        )

    def test_hint_linux_missing(self):
        hint = wifi_track._hint_for_error(
            "opcional no disponible: termux-wifi-scaninfo (escaneo cercano solo en Termux)"
        )
        self.assertIsNotNone(hint)
        self.assertIn("opcional", hint.lower())


class TestWifiLinkSnapshotLinux(unittest.TestCase):
    def setUp(self):
        runtime.clear_cache()
        os.environ["WZ_RUNTIME"] = "linux"
        runtime.clear_cache()

    def tearDown(self):
        os.environ.pop("WZ_RUNTIME", None)
        runtime.clear_cache()

    def test_monitor_gate_uses_lan(self):
        import monitor

        fake_iface = {"ip": "192.168.1.10", "prefix": 24, "name": "eth0"}
        with mock.patch("wifi_track.get_link", return_value=None):
            with mock.patch("lan_scan.resolve_iface", return_value=fake_iface):
                ok, link = monitor.wifi_link_snapshot()
        self.assertTrue(ok)
        self.assertEqual(link.get("state"), "LAN_HOST")
        self.assertEqual(link.get("ip"), "192.168.1.10")


if __name__ == "__main__":
    unittest.main()
