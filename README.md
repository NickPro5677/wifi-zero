# WiFi-ZERO

Vigilancia continua de **tu red local**. Versión 4.2, pensada para un PC o una Raspberry Pi con un panel en el teléfono.

[![CI](https://github.com/NickPro5677/wifi-zero/actions/workflows/ci.yml/badge.svg)](https://github.com/NickPro5677/wifi-zero/actions/workflows/ci.yml)
[![Licencia: MIT](https://img.shields.io/badge/licencia-MIT-blue.svg)](LICENSE)

Todo corre con la **biblioteca estándar de Python**. No hace falta `pip install`.

> **Ámbito:** este proyecto es para **tu propia red**, o con autorización. Sin root no hay modo monitor, deauth ni lectura del tráfico ajeno. Ver [docs/ETHICS.md](docs/ETHICS.md).

## Para qué sirve

Inventario de hosts (ARP + fabricante), puertos y servicios, puntuación de riesgo, listas blanca y de vigilancia, y un panel instalable en el teléfono.

La arquitectura recomendada: un **PC o Raspberry Pi** corre el cerebro (`python3 -m core`: ARP/LAN + panel HTTP). El teléfono solo abre el panel como PWA contra la IP de la red local. Termux en el móvil queda como runtime opcional. El escaneo de redes Wi-Fi cercanas (Termux:API) es opcional; el monitoreo principal es la LAN desde el Pi.

No hay demo pública: corre en tu red.

## Cómo usarlo

Guía completa: [docs/INSTALL.md](docs/INSTALL.md).

### En un Pi, Debian o Ubuntu (recomendado)

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

1. En el Pi, anota la IP de la red local (`ip -br addr`).
2. En el teléfono, abre `http://<IP-del-Pi>:8788` y sigue el asistente `/setup`.
3. Elige bind **`0.0.0.0`** solo en una red de confianza.
4. Añade la página a la pantalla de inicio (PWA).

Por defecto el panel escucha en `127.0.0.1` (más seguro). En el modelo híbrido el asistente recomienda `0.0.0.0` para que el teléfono pueda entrar. En ese caso el token viaja por HTTP en claro dentro de la Wi-Fi: ver [docs/SECURITY.md](docs/SECURITY.md).

### Termux (opcional)

Sigue funcionando si quieres el cerebro en el teléfono. Ver la sección Termux en [docs/INSTALL.md](docs/INSTALL.md). El escaneo de redes cercanas (`termux-wifi-scaninfo`) solo aplica ahí.

## Panel

- Primera vez (`/setup`): usuario, contraseña, bind (LAN para Pi + PWA) y monitor.
- Inicio de sesión: scrypt, tokens HMAC (30 min), límite de intentos y CSRF.
- Vistas: Resumen, Hosts, Radio, Topología, Eventos y Whitelist.
- Radio: el inventario LAN es lo principal; «Escanear cercanas» es opcional (Termux:API). Ver [docs/ETHICS.md](docs/ETHICS.md).
- Ajustes y Sistema: intervalos, avisos, control, comprobaciones, copias y PWA.
- Eventos en vivo (SSE), exportar CSV y atajos `/`, `s`, `1–7`, `Esc`.

## Qué rastrea

| Módulo | Técnica | Salida |
|---|---|---|
| Hosts | ARP (`ip neigh`) + TCP | IP, MAC, fabricante (OUI), estado, primera y última vez |
| Servicios | TCP + `nmap -sV` opcional | Puerto, servicio, versión |
| Wi-Fi (opcional) | Termux:API `scaninfo` / `connectioninfo` | SSID, BSSID, cifrado, canal, RSSI… |
| Sospechosos | Reglas, espera y silencio | Host nuevo, spoof, dirección aleatoria, conflicto de IP, equipo caído, AP falso/abierto/gemelo, downgrade, MITM en la puerta de enlace, puerto nuevo |
| Riesgo | Puntuación 0–100 e historial | Hosts y APs, serie `scores` |

La configuración se edita en el panel (Ajustes) o en `config.json`. Ejemplo: `config.example.json`.

## Estructura de archivos

```text
wifi-zero/
├── core/        # Supervisor, configuración, base de datos, monitor y servidor HTTP
├── scanner/     # Barrido de LAN y, opcional, de Wi-Fi
├── panel/       # PWA: inicio, setup, login, app.js, service worker y manifiesto
├── deploy/      # Unidad systemd de ejemplo (wifi-zero.service)
├── scripts/     # Contraseña (legado), watchdog y copias
├── tests/       # Pruebas con unittest, sin red
├── docs/        # INSTALL, ARCHITECTURE, RULES, SECURITY, ETHICS
└── start_all.sh # Arranca python3 -m core
```

## Tecnologías

- Python 3, solo biblioteca estándar
- SQLite
- Panel en HTML, CSS y JavaScript (PWA)
- `nmap` e `iproute2` en el sistema (opcionales según la función)
- Termux:API, solo si se escanean redes cercanas desde el teléfono

## Desarrollo

```sh
make test      # unit tests (sin red)
make check     # comprobación del conjunto
make run       # ./start_all.sh
make stop
make report
make backup
```

También:

```sh
python3 -m unittest discover -s tests -q
python3 -m core --no-monitor   # solo el panel
```

La CI usa el mismo `unittest` (sin `pip install`).

Más detalle: [docs/INSTALL.md](docs/INSTALL.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/RULES.md](docs/RULES.md), [docs/SECURITY.md](docs/SECURITY.md) y [docs/ETHICS.md](docs/ETHICS.md).

## Estado

Activo. El código en `main` corresponde a la v4.2 (cerebro en Pi o PC, teléfono como PWA). No hay *releases* publicadas ni issues abiertos. Historial en [CHANGELOG.md](CHANGELOG.md).

## Licencia

Distribuido bajo la licencia [MIT](LICENSE).
