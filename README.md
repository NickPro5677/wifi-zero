# WiFi-ZERO

Vigilancia continua de **tu red local** desde **Android/Termux sin root** (probado en Redmi
Note 11, Android 11). Rastrea todo lo que aparece y desaparece en tu Wi‑Fi, lo registra en una
SQLite y lo muestra en un panel web local con alertas.

> **Ámbito y ética.** Este entorno es para **tu propia red**. En Android **sin root** no existen
> modo monitor, deauth ni escucha del tráfico de terceros: el kernel lo bloquea. Lo que hace
> este proyecto dentro de lo legal y sin privilegios: inventario de tu red (ARP vecino + TCP),
> análisis de las redes Wi‑Fi que tu teléfono alcanza (API de Android) y seguimiento histórico
> de cambios.

---

## Qué rastrea

| Módulo | Técnica | Información |
|---|---|---|
| **Inventario de hosts** | Tabla ARP del kernel (`ip neigh`) + barrido TCP connect | IP, MAC, fabricante (OUI), estado, primera/última vista |
| **Servicios** | Probe TCP por host | puertos abiertos y proto |
| **Análisis Wi‑Fi** | `termux-wifi-scaninfo` (Termux:API) | SSID, BSSID, canal, frecuencia, RSSI, fabricante |
| **Detección** | Diff en cada ciclo aé | host nuevo (intruso), cambio de MAC (spoofing), host perdido, AP nuevo (rogue), puerto nuevo |
| **Alertas** | `termux-notification` | push en el móvil desde nivel warn |
| **Panel web** | HTTP de la stdlib | dashboard con host/AP/eventos en vivo + export CSV |

## Requisitos

```
pkg install nmap python3 termux-api
```

Concede a Termux el permiso de redes/acceso aproximado/exacto que pide Android la primera vez
que uses `termux-wifi-scaninfo` (o el panel mostrará APs vacíos).

## Uso

```sh
./start_all.sh     # arranca monitor + api + escaneo inicial
./checks.sh    # healthcheck; "TODO OK" = sano
./stop_all.sh      # detén todo
```

Panel en un navegador del mismo móvil (o de una máquina de la misma LAN):

```
http://127.0.0.1:8788
```

- `GET  /api/stats`, `/api/hosts`, `/api/aps`, `/api/events?since=N`, `/api/topology`
- `POST /api/scan` → escanear bajo demanda
- `GET  /hosts.csv` → export

## Configuración (variables)

| Variable | Defecto | Función |
|---|---|---|
| `WZ_LAN_INTERVAL` | 60 | segundos entre escaneos LAN |
| `WZ_WIFI_INTERVAL` | 120 | segundos entre análisis Wi‑Fi |
| `WZ_NOTIFY_MIN` | `warn` | nivel mínimo de alertas (`info`/`warn`/`crit`) |
| `WZ_PORT` | 8788 | puerto del panel |

## Estructura

```
wifi-zero/
├── scanner/          lan_scan.py · wifi_track.py
├── core/             db.py · monitor.py · server.py
├── panel/            index.html · app.js
├── data/wifi.db      ·   logs/  ·   start.sh · stop.sh · checks.sh
```

## Notas de seguridad

- Todo usa solo **capacidades de usuario normal**: sin root, sin monitorado, sin tráfico ajeno.
- La base de datos `data/wifi.db` vive en tu almacenamiento; valora cifrarla si te importa la
  privacidad de los registros.
- El servidor escucha en `0.0.0.0:8788`; para dejarlo solo-local cambia en `core/server.py` el
  bind a `("127.0.0.1", PORT)`.

## Hallazgos de la primera pasada en tu red

- Router `Simplefibra-7885` → `192.168.1.254`, fabricante **Nokia Shanghai Bell**, MAC
  `04:56:65:2f:f7:a0`.
- 3 hosts visibles en la tabla ARP; el resto de puertos salen **filtrados** → la red usa
  **aislamiento entre clientes** (client isolation): buena práctica, impide espionaje lateral clásico.