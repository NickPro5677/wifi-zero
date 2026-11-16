# WiFi-ZERO

Vigilancia continua de **tu red local** desde **Android/Termux sin root**
(probado en Redmi Note 11, Android 11) — **v4.0**.

Rastrea dispositivos, redes, señales y cambios de seguridad en tu Wi‑Fi,
almacena todo en SQLite y publica un **panel PWA** con login, eventos en vivo
(SSE), ajustes, control del monitor y gráficos. Todo **100 % Python stdlib**
(cero `pip install`).

> **Ámbito (imprescindible):** este proyecto es para **tu propia red** o con
> autorización. En Android sin root **no existe** monitor mode, deauth ni
> lectura del tráfico ajeno. Ver `docs/ETHICS.md`.

---

## Qué aporta en una línea
Sin root, con solo capacidades de usuario: inventario de hosts (ARP + OUI),
puertos/servicios, análisis Wi‑Fi, motor anti‑intrusión, scoring de riesgo,
whitelist/watchlist y un **panel instalable** que sustituye la terminal en el
día a día.

## Rápido — arrancar (una vez)

```sh
cd ~/wifi-zero
./start_all.sh          # supervisor: panel + monitor
# Abre http://127.0.0.1:8788 → wizard /setup (primera vez)
# Luego: Añadir a pantalla de inicio (PWA)
```

La terminal solo hace falta para ese arranque (o Termux:Widget / boot).
Contraseña, intervalos, pushes, start/stop, checks y backup: **desde el panel**.

Legado (recuperación): `python3 scripts/set_password.py`, `./checks.sh`.

## Panel (v4)

- **First-run** `/setup`: usuario, contraseña, bind local vs LAN, arrancar monitor.
- **Login** (scrypt, tokens HMAC, 30 min, throttling, CSRF).
- **Resumen / Hosts / Radio / Topología / Eventos / Whitelist**.
- **Ajustes**: intervalos (LAN y Wi‑Fi independientes), batería, puertos, pushes,
  pesos de riesgo, silenciar reglas, cambio de password.
- **Sistema**: start/pause/resume/restart/stop, checks JSON, backup, logs, instalar PWA.
- **SSE** en vivo, export CSV (hosts y eventos), atajos `/` `s` `1–7` `Esc`.

## Qué rastrea

| Módulo | Técnica | Salida |
|---|---|---|
| Hosts | ARP (`ip neigh`) + TCP | IP, MAC, OUI, estado, 1ª/última |
| Servicios | TCP + `nmap -sV` opcional | puerto, servicio, versión |
| Wi-Fi | Termux:API scaninfo/connectioninfo | cifrado, canal, banda, hidden, DFS |
| Sospechosos | reglas + cooldown + mute | host nuevo, spoof, LAA, conflicto IP, offline, AP rogue/open/twin, downgrade, gateway MITM, puerto nuevo |
| Riesgo | scoring 0–100 + historial | hosts/APs + serie `scores` |

## Configuración

Editable en el panel (Ajustes) o en `config.json`. Ejemplo: `config.example.json`.

- `intervalos.wifi` gobierna el ciclo Wi‑Fi (independiente del LAN).
- `muted_rules`: `{ "new_host": <unix_ts\|-1> }` silencia reglas.
- Retención, watchlist, threat weights, pushes: mismos campos que v3.

## Makefile

```sh
make test      # unit tests (sin red)
make check     # healthcheck del stack
make run/stop
make report
make backup
```

## Estructura

```
wifi-zero/
├── core/        supervisor · config · db · monitor · server · rules · threat · …
├── scanner/     lan_scan · wifi_track
├── panel/       PWA (index, setup, login, app.js, sw.js, manifest)
├── scripts/     set_password (legado) · watchdog · backup
├── tests/
├── docs/        ARCHITECTURE · RULES · SECURITY · ETHICS
└── start_all.sh → python3 -m core
```

## Dev

```sh
python3 -m unittest discover tests
python3 -m core --no-monitor   # solo panel
```

---
Más: `docs/ARCHITECTURE.md`, `docs/RULES.md`, `docs/SECURITY.md`, `docs/ETHICS.md`.
