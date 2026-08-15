# Arquitectura

## Visión general
wifi-zero es un sistema de **vigilancia pasiva/activa de la propia red local** que
corre íntegramente en Termux (Android) **sin root**. Todo en Python 3.14 stdlib.

```
┌────────────┐   ┌───────────────────────┐   ┌─────────────┐   ┌──────────────────┐
│ monitor.py │──▶│ lan_scan.py  (ARP+TCP) │──▶│    SQLite   │◀──│ server.py (panel) │
│  (loop)    │──▶│ wifi_track.py (API)    │──▶│  wifi.db    │   │   stdlib HTTP    │
│            │   │ sb_scan (nmap -sV/NSE) │   │ (migrado v2)│──▶│ SSE · auth · SVG │
└────────────┘   └───────────────────────┘   └─────────────┘   └──────────────────┘
      │ print/log                                ▲                    │
      └─▶ rules.py ─channel_eventos→ notifications (notify.py)
```

## Módulos

- `core/config.py` — carga y valida `config.json` sobre defaults.
- `core/db.py` — conexión SQLite + **migraciones versionadas** (v1→v2). Al
  añadir features: añade una entrada a `MIGRATIONS`, no edites las publicadas.
- `core/monitor.py` — bucle: scan LAN + WiFi → motor de reglas → eventos/notif.
  Battery-aware (pausa < 15 % sin carga) y gated por `supplicant_state`.
- `core/rules.py` — reglas con cooldown por entidad (new_host, spoof, offline,
  new_ap, downgrade cifrado, evil-twin, new_port, watchlist).
- `core/threat.py` — scoring 0–100 + tiers (ok/warn/crit).
- `core/notify.py` — termux-notification local + push opcional ntfy/Telegram.
- `core/auth.py` — scrypt (hashlib, sin bcrypt) + tokens HMAC-SHA256 con expiración.
- `core/server.py` — panel HTTP stdlib: REST + SSE + SVG. Auth opcional.
  SSE relee SQLite (`_sse_pump`) porque el monitor es otro proceso.
  `/api/dashboard` y `/api/health` alimentan la GUI v3.1.
- `scanner/lan_scan.py` — detección hosts por `ip neigh` (tabla ARP) + TCP
  connect; nmap -sV opcional; NSE broadcast (DNS-SD/SSDP).
- `scanner/wifi_track.py` — Termux:API `wifi-scaninfo` + `connectioninfo` con
  parse de `capabilities` (cifrado/channel/hidden).
- `core/report.py` — reporte Markdown diario.

## Ciclo de vida de datos

1. El monitor arranca y registra su PID (`logs/monitor.pid`).
2. Por ciclo escribe `runs`; cada host nuevo/gone/port → `events`; cada AP/estación
   → `aps`/`stations`/`signals` (telemetría histórica).
3. El panel lee SQLite en cada request y el SSE entrega eventos a los clientes.

## Decisiones clave

- **Zero deps**: Python stdlib (http.server, sqlite3, hashlib.scrypt, threads).
- **Migraciones**: `schema_version` real, no `CREATE IF NOT EXISTS` a ciegas.
- El bind del panel es `0.0.0.0` por defecto; para no exponerlo usa
  `panel.bind=127.0.0.1` en `config.json`.