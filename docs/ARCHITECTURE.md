# Arquitectura

## Visión general (v4.2 — híbrido)
wifi-zero vigila **tu propia red local**. El runtime **primario** es un
**PC o Raspberry Pi** (Debian/Ubuntu/Raspberry Pi OS). El teléfono es un
**cliente PWA** contra el panel HTTP del Pi. Termux/Android queda como
runtime **opcional/legado**.

Todo en Python 3 stdlib (cero `pip`).

```
┌────────────────────┐         ┌──────────────────┐
│  Pi / PC (brain)   │  HTTP   │  Teléfono (PWA)  │
│  python3 -m core   │◄───────►│  navegador /     │
│  supervisor.py     │   LAN   │  pantalla inicio │
└─────────┬──────────┘         └──────────────────┘
          │
   ┌──────┴───────┐
   ▼              ▼
monitor (hilo)   server.py (HTTP + control API)
   │                  │
   ▼                  ▼
lan_scan (ARP)        │
wifi_track (opc.)     │
   │                  │
   └────► SQLite ◄────┘
```

- **Primario:** `lan_scan` (ARP / `ip neigh` + TCP) en el Pi.
- **Opcional:** `wifi_track` (Termux:API) — redes cercanas; no bloquea el monitor en Linux.

## Módulos

- `core/supervisor.py` — entrypoint: panel + lifecycle del monitor.
- `core/runtime.py` — detección Linux vs Termux, rutas (`ip`, nmap, OUI, Termux:API).
- `core/config.py` — carga/valida/guarda `config.json`; `public_dict`, `setup_needed`.
- `core/db.py` — SQLite + migraciones versionadas.
- `core/monitor.py` — bucle LAN (y Wi‑Fi si hay herramientas); en Linux no exige association Termux.
- `core/rules.py` / `core/threat.py` — detección y scoring.
- `core/server.py` — REST + SSE + PWA estáticos + plano de control.
- `core/checks.py` — healthchecks (Termux:API opcional en Linux) y backup.
- `core/auth.py` — scrypt + tokens HMAC.
- `scanner/lan_scan.py` / `wifi_track.py` — adquisición; Wi‑Fi soft-fail si falta Termux:API.
- `panel/` — SPA/PWA (setup con hints de runtime, ajustes, radio).
- `deploy/wifi-zero.service` — unidad systemd de ejemplo.
- API Wi‑Fi: `GET/POST /api/wifi/scan`, `GET /api/wifi/link` (opcional).

## Ciclo de vida

1. `start_all.sh` / systemd → `python3 -m core` (supervisor).
2. Si no hay password → panel redirige a `/setup`.
3. Tras setup (o si ya hay password) el monitor arranca solo.
4. El usuario opera start/stop/config/checks/backup desde el navegador/PWA
   (en el teléfono contra la IP del Pi).

## Decisiones clave

- **Zero deps** Python stdlib.
- **Pi-first / PWA client**: la terminal no es la UI diaria; Termux no es el host requerido.
- **Migraciones append-only** en `db.py`.
- Bind por defecto `127.0.0.1`; en `/setup` el host Linux recomienda `0.0.0.0`
  para LAN+PWA. Ver `docs/SECURITY.md`.
- Watchdog: systemd en Pi; `scripts/watchdog.sh` en Termux legado.
