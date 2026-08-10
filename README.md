# WiFi-ZERO

Vigilancia continua de **tu red local** desde **Android/Termux sin root**
(probado en Redmi Note 11, Android 11) — v3.

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
| Servicios | probe TCP + `nmap -sV` (opcional, cadencia `sv`) | puerto, servicio, producto, versión |
| Wi-Fi | Termux:API `scaninfo`/`connectioninfo` | cifrado (WPA2/WPA3/OPEN), canal, banda 2.4/5/6 GHz, bandwidth, SSID oculto, DFS |
| Sospechosos | motor de reglas (cooldown c/entidad) | host nuevo, spoof MAC, MAC randomizada (LAA), conflicto de IP, offline, AP new/rogue/open, downgrade cifrado, evil-twin, **cambio de MAC del gateway (MITM)**, puerto nuevo |
| Riesgo | scoring 0–100 + tier (host *y* AP) | hosts ordenados + **serie histórica de riesgo** por host |
| Historia | `hosts_history`/`signals`/`scores` | uptime, señal y evolución de riesgo por host/AP |
| Higiene | WAL + `prune()` por retención | la DB no crece sin límite (config `retention`) |

## Panel (F4)

- **Login** (scrypt, tokens HMAC, 30 min, throttling 5/10min, CSRF) — activo
  por defecto; el SSE y las APIs llevan el token en cabecera (no en la URL).
- **Dashboard**: KPIs, tabla de hosts ordenable por riesgo, filtro de búsqueda,
  solo críticos.
- **detalle de host** (`/host.html?ip=…`): historia, puertos, eventos, **riesgo
  histórico** y acciones de confianza directas (confiar / bloquear / quitar).
- **Whitelist** gestionable desde la consola (añadir, etiquetar, quitar).
- **APs**: canal, banda, RSSI, cifrado, **riesgo por AP**; clic → gráfico de señal.
- **Redes memorizadas** y **estación actual** (link_speed, network_id).
- **Eventos en vivo** vía SSE (fetch-streaming) con filtro «solo alertas».
- **Export** CSV (valores escapados, compatible con hojas de cálculo).

## Configuración

`config.json` (los valores por defecto bastan):

```json
{
  "intervalos": { "lan": 60, "wifi": 120, "sv": 300 },
  "notify":     { "min_level": "warn", "channel": "wifi-zero" },
  "panel":      { "port": 8788, "bind": "0.0.0.0", "auth": true, "user": "admin", "password": "<scrypt hash>" },
  "battery":    { "eco_below": 35, "pause_below": 15 },
  "scanner":    { "ports_scan": [...], "nse_broadcast": true, "service_versions": true },
  "pushes":     { "enabled": false, "ntfy_url": "", "telegram_token": "", "telegram_chat": "" },
  "watchlist":  [],
  "retention":  { "signals": 7, "hosts_history": 14, "scores": 30, "stations": 7, "events": 30, "ports_closed": 7 },
  "gateway_watch": true,
  "threat":     { "weights": { "untrusted": 25, "unknown": 10, "no_vendor": 15, "random_mac": 15, "per_port": 6, "max_ports": 30, "weak_svc": 10, "danger_port": 15 } }
}
```

- Cambia la contraseña: `python3 scripts/set_password.py`
- Push en otro dispositivo (nfty/Telegram): completa `pushes` y pon `enabled: true`.
- Watchlist: pon `{ "mac": "..", "label": "Router" }` para que su caída salte crítica.
- Retención: ajusta `retention` (días); la purga corre sola cada 24 h en el monitor.
- Modo eco: con batería < `eco_below` y desenchufado, el monitor duplica los
  intervalos y omite `nmap -sV` hasta que vuelvas a cargar.

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