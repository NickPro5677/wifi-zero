# WiFi-ZERO

Vigilancia continua de **tu red local** — **v4.2** (híbrido).

**Arquitectura recomendada:** un **PC o Raspberry Pi** corre el cerebro
(`python3 -m core`: ARP/LAN + panel HTTP). El **teléfono solo abre el panel**
como PWA contra la IP LAN del Pi. Termux en el móvil queda como runtime
**opcional/legado**.

Todo **100 % Python stdlib** (cero `pip install`).

> **Ámbito (imprescindible):** este proyecto es para **tu propia red** o con
> autorización. Sin root **no hay** monitor mode, deauth ni lectura del tráfico
> ajeno. Ver `docs/ETHICS.md`.

---

## Qué aporta en una línea
Inventario de hosts (ARP + OUI), puertos/servicios, scoring de riesgo,
whitelist/watchlist y un **panel instalable** en el teléfono. El escaneo Wi‑Fi
cercano vía Termux:API es **opcional**; el monitoreo primario es LAN desde el Pi.

## Rápido — Pi / Debian / Ubuntu (recomendado)

Guía completa: **[`docs/INSTALL.md`](docs/INSTALL.md)**.

```sh
sudo apt update
sudo apt install -y python3 nmap iproute2 curl
git clone https://github.com/NickPro5677/wifi-zero.git
cd wifi-zero

# secreto HMAC persistente (imprescindible)
mkdir -p ~/.wifi-zero
python3 -c "import secrets; print(secrets.token_hex(32))" > ~/.wifi-zero/session_secret
chmod 600 ~/.wifi-zero/session_secret
export WZ_SESSION_SECRET="$(cat ~/.wifi-zero/session_secret)"

./start_all.sh          # o: sudo systemctl enable --now wifi-zero
# (unidad de ejemplo: deploy/wifi-zero.service)
```

1. En el Pi, anota la IP LAN (`ip -br addr`).
2. En el **teléfono**, abre `http://<IP-del-Pi>:8788` → wizard `/setup`.
3. Elige bind **`0.0.0.0`** (LAN) en red de confianza.
4. «Añadir a pantalla de inicio» (PWA).

Bind por defecto en config: `127.0.0.1` (seguro). En el modelo híbrido el
wizard recomienda `0.0.0.0` para el teléfono — ver `docs/SECURITY.md`
(Bearer por HTTP en claro en la Wi‑Fi).

## Termux (opcional / legado)

Sigue funcionando si quieres el cerebro en el teléfono. Ver sección Termux
en `docs/INSTALL.md`. El escaneo de redes cercanas (`termux-wifi-scaninfo`)
solo aplica ahí.

## Panel (v4)

- **First-run** `/setup`: usuario, contraseña, bind (LAN para Pi+PWA), monitor.
- **Login** (scrypt, tokens HMAC, 30 min, throttling, CSRF).
- **Resumen / Hosts / Radio / Topología / Eventos / Whitelist**.
- **Radio**: inventario LAN es primario; «Escanear cercanas» es opcional
  (Termux:API). Ver `docs/ETHICS.md`.
- **Ajustes / Sistema**: intervalos, pushes, control, checks, backup, PWA.
- **SSE** en vivo, export CSV, atajos `/` `s` `1–7` `Esc`.

## Qué rastrea

| Módulo | Técnica | Salida |
|---|---|---|
| Hosts | ARP (`ip neigh`) + TCP | IP, MAC, OUI, estado, 1ª/última |
| Servicios | TCP + `nmap -sV` opcional | puerto, servicio, versión |
| Wi-Fi (opcional) | Termux:API scaninfo/connectioninfo | SSID, BSSID, cifrado, canal, RSSI… |
| Sospechosos | reglas + cooldown + mute | host nuevo, spoof, LAA, conflicto IP, offline, AP rogue/open/twin, downgrade, gateway MITM, puerto nuevo |
| Riesgo | scoring 0–100 + historial | hosts/APs + serie `scores` |

## Configuración

Editable en el panel (Ajustes) o en `config.json`. Ejemplo: `config.example.json`.

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
├── core/        supervisor · runtime · config · db · monitor · server · …
├── scanner/     lan_scan · wifi_track (opcional)
├── panel/       PWA (index, setup, login, app.js, sw.js, manifest)
├── deploy/      wifi-zero.service (systemd)
├── scripts/     set_password (legado) · watchdog · backup
├── tests/
├── docs/        INSTALL · ARCHITECTURE · RULES · SECURITY · ETHICS
└── start_all.sh → python3 -m core
```

## Dev

```sh
python3 -m unittest discover -s tests -q
python3 -m core --no-monitor   # solo panel
```

CI usa el mismo `unittest` (sin `pip install`).

---
Más: `docs/INSTALL.md`, `docs/ARCHITECTURE.md`, `docs/RULES.md`,
`docs/SECURITY.md`, `docs/ETHICS.md`.
