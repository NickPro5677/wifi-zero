# Arquitectura

## Visión general (v4)
wifi-zero es un sistema de **vigilancia pasiva/activa de la propia red local** que
corre íntegramente en Termux (Android) **sin root**. Todo en Python 3 stdlib.

```
┌────────────────────┐
│  python3 -m core   │  ← arranque único (start_all.sh)
│  supervisor.py     │
└─────────┬──────────┘
          │
   ┌──────┴───────┐
   ▼              ▼
monitor (hilo)   server.py (HTTP + control API)
   │                  │
   ▼                  ▼
lan_scan / wifi_track │
   │                  │
   └────► SQLite ◄────┘
              ▲
              │
         panel/ PWA
```

## Módulos

- `core/supervisor.py` — entrypoint: panel + lifecycle del monitor.
- `core/config.py` — carga/valida/guarda `config.json`; `public_dict`, `setup_needed`.
- `core/db.py` — SQLite + migraciones versionadas.
- `core/monitor.py` — bucle LAN/Wi‑Fi independientes, battery-aware, stop Event.
- `core/rules.py` / `core/threat.py` — detección y scoring.
- `core/server.py` — REST + SSE + PWA estáticos + plano de control.
- `core/checks.py` — healthchecks y backup (API).
- `core/auth.py` — scrypt + tokens HMAC.
- `scanner/lan_scan.py` / `wifi_track.py` — adquisición sin root.
  Wi‑Fi: solo Termux:API (`scaninfo`/`connectioninfo`); campos legales;
  `scan_nearby()` + backoff de reconexión en el monitor.
- `panel/` — SPA/PWA (setup, ajustes, sistema, radio/cercanas, a11y).
- API Wi‑Fi: `GET/POST /api/wifi/scan`, `GET /api/wifi/link`.

## Ciclo de vida

1. `start_all.sh` → `python3 -m core` (supervisor).
2. Si no hay password → panel redirige a `/setup`.
3. Tras setup (o si ya hay password) el monitor arranca solo.
4. El usuario opera start/stop/config/checks/backup solo desde el navegador/PWA.

## Decisiones clave

- **Zero deps** Python stdlib.
- **PWA-first**: la terminal no es la UI diaria.
- **Migraciones append-only** en `db.py`.
- Bind por defecto `127.0.0.1` (Bearer no en claro en la LAN); en `/setup` se
  puede elegir `0.0.0.0` conscientemente. Ver `docs/SECURITY.md`.
- Watchdog / boot: `scripts/watchdog.sh` reinicia `python3 -m core` vía
  `logs/supervisor.pid` (no monitor+server separados).
