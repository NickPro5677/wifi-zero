# -*- coding: utf-8 -*-
"""Motor de inteligencia (F2): reglas con cooldown, whitelist y threat score.

El monitor evalúa estas reglas en cada ciclo. Cada regla tiene un cooldown
por entidad (IP/MAC/BSSID) para evitar ruido. La fuente de verdad de eventos
es `events` en SQLite (que el panel lee en vivo).
"""
import time
from collections import defaultdict

LEVELS = {"info": 0, "warn": 1, "crit": 2}

# cooldown (s) por regla
COOLDOWNS = {
    "new_host": 60,
    "mac_change": 300,
    "offline": 600,
    "new_ap": 900,
    "ap_encryption_downgrade": 1800,
    "ap_twin": 360,
    "new_port": 300,
    "watchlist_down": 300,
    "watchlist_unknown": 600,
    "ap_reconnect": 120,
    "mac_randomized": 1800,
    "ip_conflict": 600,
    "gateway_changed": 1800,
    "ap_open": 1800,
}


class Rules:
    def __init__(self, con, cfg, emit):
        self.con = con
        self.cfg = cfg
        self.emit = emit  # callable(rule, level, msg, ip, mac)
        self._last = defaultdict(float)

    def _allowed(self, rule, entity):
        now = time.time()
        if now - self._last[(rule, entity)] < COOLDOWNS.get(rule, 0):
            return False
        self._last[(rule, entity)] = now
        return True

    def _dedupe(self, rule, level, message, ip=None, mac=None):
        """Emite solo si pasa el cooldown de (rule, entity)."""
        entity = ip or mac or message[:60]
        if not self._allowed(rule, entity):
            return False
        return self.emit(rule, level, message, ip=ip, mac=mac)

    # ------------------------------------------------------------ helpers
    def _critical_label(self, mac):
        wl = self.cfg.get("watchlist", default=[])
        for e in wl:
            if e.get("mac", "").lower() == (mac or "").lower():
                return e.get("label", "crítico")
        return None

    def _trusted(self, mac):
        mac = (mac or "").lower()
        if not mac:
            return None
        row = self.con.execute("SELECT trusted FROM whitelist WHERE mac=?", (mac,)).fetchone()
        return bool(row["trusted"]) if row else None

    # ------------------------------------------------------------ reglas hosts
    def host_seen(self, ip, mac, vendor=None, is_new=False, replaced_mac=None):
        """Evento por host detectado: nuevo, spoofing de MAC, desconocido."""
        trusted = self._trusted(mac or replaced_mac)
        if is_new:
            if trusted is False:
                self._dedupe("new_host", "crit",
                             f"Intruso (MAC no confiable) entró en la red: {ip} "
                             f"({mac or '?'}, {vendor or '?'})", ip=ip, mac=mac)
            elif not trusted:
                self._dedupe("new_host", "warn",
                             f"Nuevo host en la red: {ip} ({mac}, {vendor or '?'})",
                             ip=ip, mac=mac)
        # spoofing: misma ip ahora responde con otra MAC
        if replaced_mac and mac and replaced_mac != mac:
            self._dedupe("mac_change", "crit",
                         f"IP {ip} CAMBIÓ de MAC {replaced_mac} → {mac} (¿spoofing?)",
                         ip=ip, mac=mac)
        # dispositivo crítico que ya no está (offline) o contenido
        label = self._critical_label(mac)
        if label and not trusted:
            self._dedupe("watchlist_unknown", "warn",
                         f"Dispositivo watchlist ' {label}' ({mac}) llegó DESCONOCIDO", ip=ip, mac=mac)

    def mac_randomized(self, ip, mac, vendor=None):
        """MAC con bit localmente administrado ⇒ identidad randomizada."""
        self._dedupe("mac_randomized", "warn",
                     f"MAC randomizada (LAA) detectada: {ip} ({mac}, {vendor or '?'}) "
                     f"— ¿privacidad o evasión?", ip=ip, mac=mac)

    def ip_conflict(self, ip, macs, vendors=None):
        """Dos MAC distintas respondiendo por la misma IP (conflicto/ARP spoof)."""
        self._dedupe("ip_conflict", "crit",
                     f"CONFLICTO DE IP: {ip} responde con {', '.join(str(m) for m in macs[:3])}",
                     ip=ip, mac=macs[0] if macs else None)

    def gateway_changed(self, old_mac, new_mac, gw_ip):
        """Cambió la MAC de la puerta de enlace (posible MITM)."""
        self._dedupe("gateway_changed", "crit",
                     f"⚠ GATEWAY {gw_ip} cambió de MAC {old_mac} → {new_mac} (¿MITM?)",
                     ip=gw_ip, mac=new_mac)

    def host_offline(self, ip, mac, critical_label=None):
        trusted = self._trusted(mac)
        if critical_label and not trusted:
            self._dedupe("watchlist_down", "crit",
                         f"⚠ DISPOSITIVO CRÍTICO OFFLINE: {critical_label} ({ip}, {mac})",
                         ip=ip, mac=mac)
        elif trusted is not False:
            self._dedupe("offline", "info", f"Host fuera de red: {ip}", ip=ip, mac=mac)

    def port_new(self, ip, port, service=None):
        self._dedupe("new_port", "warn",
                     f"Puerto abierto nuevo en {ip}: {port}/tcp ({service or '?'})", ip=ip)

    def ap_new(self, ap):
        bssid, ssid = ap.get("bssid"), ap.get("ssid")
        self._dedupe("new_ap", "warn",
                     f"AP nuevo visible: {ssid or '<oculto>'} (BSSID {bssid}, canal {ap.get('channel')}, "
                     f"RSSI {ap.get('rssi')}, {'WPA3' if ap.get('encryption') == 'WPA3' else ap.get('encryption')})",
                     ip=None, mac=bssid)
        if not ap.get("encryption") or ap.get("encryption") == "OPEN":
            self._dedupe("ap_open", "crit",
                         f"AP ABIERTO (SIN CIFRADO) visible: {ssid or '<oculto>'} "
                         f"(BSSID {bssid}, canal {ap.get('channel')})", ip=None, mac=bssid)

    def ap_encryption_downgrade(self, ap, old_enc, new_enc):
        self._dedupe("ap_encryption_downgrade", "crit",
                     f"ALERTA: BSSID {ap.get('bssid')} bajó cifrado {old_enc}→ {new_enc}", mac=ap.get("bssid"))

    def ap_twin(self, ssid):
        """Mismo SSID visto con varias BSSIDs (posible evil-twin)."""
        self._dedupe("ap_twin", "warn",
                     f"SSID clonado/doble visible: '{ssid}' (posible evil-twin)", ip=None, mac=None)

    def link_dropped(self, st):
        self._dedupe("ap_released", "info",
                     "El teléfono salió de la red WiFi (scan pausado hasta reconectar)")