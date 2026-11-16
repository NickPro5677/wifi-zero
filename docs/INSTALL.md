# Instalación — híbrido Pi/PC + PWA (recomendado)

El **cerebro** corre en Linux (Debian / Ubuntu / Raspberry Pi OS). El
**teléfono solo abre el panel** (navegador → PWA). Termux queda documentado
al final como camino opcional/legado.

## Checklist first-run (Pi + teléfono)

| # | Paso | Verificación |
|---|------|----------------|
| 1 | `apt install python3 nmap iproute2 curl` | `python3 --version`, `nmap -V`, `ip -br addr` |
| 2 | Clonar repo y `export WZ_SESSION_SECRET=…` | `echo "$WZ_SESSION_SECRET" \| wc -c` ~65 |
| 3 | Arrancar (`./start_all.sh` o systemd) | `logs/supervisor.pid` vivo / `systemctl status wifi-zero` |
| 4 | Anotar IP LAN del Pi | p. ej. `192.168.1.50` |
| 5 | En el teléfono: `http://<IP>:8788` → `/setup` | Usuario + contraseña |
| 6 | Bind **`0.0.0.0`** (LAN de confianza) | Panel alcanzable desde el móvil |
| 7 | Instalar PWA («Añadir a pantalla de inicio») | Icono en el launcher |
| 8 | Panel → Sistema → Checks | Interfaz LAN + OUI + panel OK; Wi‑Fi scan = opcional |

---

## 1. Paquetes (Debian / Ubuntu / Raspberry Pi OS)

```sh
sudo apt update
sudo apt install -y python3 nmap iproute2 curl git
```

No hace falta `pip`. `nmap` aporta el OUI (`/usr/share/nmap/nmap-mac-prefixes`).

## 2. Clonar y secreto de sesión

```sh
cd ~
git clone https://github.com/NickPro5677/wifi-zero.git
cd wifi-zero

mkdir -p ~/.wifi-zero
python3 -c "import secrets; print(secrets.token_hex(32))" > ~/.wifi-zero/session_secret
chmod 600 ~/.wifi-zero/session_secret
echo 'export WZ_SESSION_SECRET="$(cat ~/.wifi-zero/session_secret)"' >> ~/.bashrc
export WZ_SESSION_SECRET="$(cat ~/.wifi-zero/session_secret)"
```

Sin `WZ_SESSION_SECRET`, cada reinicio invalida el login (HMAC nuevo).

## 3. Arranque manual

```sh
./start_all.sh
# o: python3 -m core
```

Abre en el Pi `http://127.0.0.1:8788` o, desde el teléfono (tras setup con
bind LAN), `http://<IP-del-Pi>:8788`.

## 4. systemd (recomendado en Pi)

Hay una unidad de ejemplo en [`deploy/wifi-zero.service`](../deploy/wifi-zero.service).

Resumen:

```sh
sudo useradd -r -s /usr/sbin/nologin -d /opt/wifi-zero wifi-zero || true
sudo mkdir -p /opt/wifi-zero /etc/wifi-zero
sudo rsync -a --exclude .git ./ /opt/wifi-zero/
sudo chown -R wifi-zero:wifi-zero /opt/wifi-zero

sudo install -m 600 /dev/null /etc/wifi-zero/session_secret
python3 -c "import secrets; print(secrets.token_hex(32))" \
  | sudo tee /etc/wifi-zero/session_secret >/dev/null
sudo chown wifi-zero:wifi-zero /etc/wifi-zero/session_secret

# Edita WorkingDirectory/User si hace falta, luego:
sudo cp /opt/wifi-zero/deploy/wifi-zero.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wifi-zero
sudo systemctl status wifi-zero
```

## 5. Teléfono = cliente PWA

1. Conéctate a la **misma Wi‑Fi** que el Pi.
2. Abre `http://<IP-del-Pi>:8788`.
3. Completa `/setup` si es la primera vez (usuario, contraseña, bind LAN).
4. En el navegador: **Añadir a pantalla de inicio** / Instalar app.
5. Opera start/stop, ajustes, hosts y eventos desde la PWA — sin Termux.

### Bind y seguridad

- `127.0.0.1` — solo procesos locales del Pi (seguro; el teléfono no llega).
- `0.0.0.0` — necesario para la PWA en el móvil. HTTP **sin TLS**: el Bearer
  viaja en claro en tu LAN. Solo en red de confianza; ver `docs/SECURITY.md`.

## 6. Escaneo Wi‑Fi cercano (opcional)

En el Pi **no** hace falta Termux:API. El inventario de hosts usa ARP/LAN.
«Escanear cercanas» en Radio solo aplica si aún corres wifi-zero (o las
herramientas) en un teléfono con Termux:API + permisos.

---

## Termux (opcional / legado)

Úsalo solo si quieres el cerebro en el Android. El camino principal es Pi+PWA.

### Paquetes

```sh
pkg update
pkg install python nmap termux-api termux-services curl
```

Instala la app **Termux:API**. Permisos: ubicación + Wi‑Fi cercanas (Android 13+).

### Arranque

```sh
cd ~/wifi-zero
# mismo WZ_SESSION_SECRET que arriba
./start_all.sh
# Abre http://127.0.0.1:8788 → /setup
```

### Termux:Boot / Widget

Preferible migrar a systemd en un Pi. Si permaneces en Termux:

`~/.termux/boot/wifi-zero.sh` → `bash scripts/watchdog.sh` (ver historial del repo
o comentarios en `scripts/watchdog.sh`).

---

## Notas

- **Zero pip**: CI y local usan `unittest` stdlib.
- Recuperación de contraseña (legado): `python3 scripts/set_password.py`.
- Checks: `./checks.sh` o panel → Sistema → Checks (Termux:API marcado opcional en Linux).
