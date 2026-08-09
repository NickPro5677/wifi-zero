# WiFi-ZERO

Vigilancia continua de **tu red local** desde **Android/Termux sin root**
(probado en Redmi Note 11, Android 11) — v2.

Rastrea dispositivos, redes, señales y cambios de seguridad en tu Wi‑Fi,
almacena todo en SQLite (migrado) y publica un panel web local con **login**,
**eventos en vivo** (SSE), análisis de riesgo y gráficos. Todo **100 % Python
stdlib** (cero `pip install`).

> **Ámbito (imprescindible):** este proyecto es para **tu propia red** o con
> autorización. En Android sin root **no existe** monitor mode, deauth ni
> lectura del tráfico ajeno; hacemos exactamente lo permitido y útil para
> proteger tu hogar. Ver `docs/ETHICS.md`.

---

## Qué aporta en una línea
Sin root, con solo capacidades de usuario, wifi-zero te da: inventario de
hosts (ARP vecino + fabricante OUI), puertos/servicios, análisis Wi‑Fi
profundo (cifrado, canal, SSID oculto, BSSID duplicado), motor de reglas
anti‑intrusión con cooldown, scoring de riesgo por host, whitelist/watchlist
y un panel web seguro con token.

## Rápido — arrancar

```sh
cd ~/wifi-zero
python3 scripts/set_password.py     # define la contraseña del panel
./start_all.sh                      # monitor + panel + portada
./checks.sh                         # TODO OK = sano
```

Panel: `http://127.0.0.1:8788`  (usuario por defecto `admin`, la que fijes).

## Qué rastrea (v2)

| Módulo | Técnica | Salida |
|---|---|---|
| Hosts | ARP del kernel (`ip neigh`) + TCP connect | IP, MAC, fabricante (OUI), estado, 1ª/última |
| Servicios | probe TCP + `nmap -sV` (opcional) | puerto, servicio, producto, versión |
| Wi-Fi | Termux:API `scaninfo`/`connectioninfo` | cifrado (WPA2/WPA3/OPEN), canal, bandwidth, SSID oculto, dispositivo actual |
| Sospechosos | motor de reglas (cooldown c/entidad) | host nuevo, spoof MAC, offline, AP new/rogue, downgrade cifrado, evil-twin, puerto nuevo |
| Riesgo | scoring 0–100 + tier | cada host en el panel ordenado |
| Historia | `hosts_history`/`signals` | uptime y señal por host/AP |

## Panel (F4)

- **Login** (scrypt, tokens HMAC, 30 min) — activo por defecto.
- **Dashboard**: KPIs, tabla de hosts ordenable por riesgo, filtro de búsqueda,
  solo críticos.
- **detalle de host** (`/host.html?ip=…`): historia, puertos, eventos.
- **APs**: canal, RSSI, cifrado, fabricante; clic → gráfico SVG de señal.
- **Redes memorizadas** y **estación actual** (link_speed, network_id).
- **Eventos en vivo** vía SSE (pestaña a pestaña se actualiza al instante).
- **Export** CSV.

## Configuración

`config.json` (los valores por defecto bastan):

```json
{
  "intervalos": { "lan": 60, "wifi": 120 },
  "notify":     { "min_level": "warn", "channel": "wifi-zero" },
  "panel":      { "port": 8788, "bind": "0.0.0.0", "auth": true, "user": "admin", "password": "<scrypt hash>" },
  "battery":    { "eco_below": 35, "pause_below": 15 },
  "scanner":    { "ports_scan": [...], "nse_broadcast": true, "service_versions": true },
  "pushes":     { "enabled": false, "ntfy_url": "", "telegram_token": "", "telegram_chat": "" },
  "watchlist":  []
}
```

- Cambia la contraseña: `python3 scripts/set_password.py`
- Push en otro dispositivo (nfty/Telegram): completa `pushes` y pon `enabled: true`.
- Watchlist: pon `{ "mac": "..", "label": "Router" }` para que su caída salte crítica.

## Makefile

```sh
make test      # unit tests (sin red)
make check     # healthcheck del stack
make run/stop
make report    # reporte Markdown
make backup
```

## Estructura

```
wifi-zero/
├── core/        config · db(+migraciones) · log · auth · rules ·
│                threat · notify · monitor · server · report
├── scanner/      lan_scan (ip neigh + nmap) · wifi_track (API)
├── panel/        index.html · host.html · login.html · app.js · style.css
├── scripts/      set_password.py · watchdog.sh · backup.sh
├── tests/        test_wifi_zero.py
├── config.json · Makefile · checks.sh · start_all.sh · stop_all.sh
├── data/         wifi.db (gitignored) · reports/ · backups/
└── docs/         ARCHITECTURE · RULES · SECURITY · ETHICS
```

## Dev

- prueba sin red: `python3 -m unittest discover tests`
- nuevos módulos: mira `docs/ARCHITECTURE.md`, añade migraciones a `core/db.py`.
- logs: `logs/wifi-zero.log` (rotación diaria), `logs/monitor.log`, `logs/server.log`.

---
Más: `docs/ARCHITECTURE.md` (cómo encaja el spam), `docs/RULES.md` (reglas y
cooldown), `docs/SECURITY.md` (panel/auth), `docs/ETHICS.md` (uso lícito).