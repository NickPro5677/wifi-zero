# Instalación — Termux (Android, sin root)

Checklist canónico para el primer día. Tras esto, el día a día es el panel/PWA.

## 1. Paquetes Termux

```sh
pkg update
pkg install python nmap termux-api termux-services curl
```

Opcional pero útil para arranque al encender / Widget:

```sh
pkg install termux-widget   # atajos en la pantalla de inicio
# Termux:Boot se instala desde F-Droid / Play como app aparte
```

Instala también la app **Termux:API** (F-Droid/Play) — sin ella no hay
`termux-wifi-scaninfo` / `termux-wifi-connectioninfo` / batería.

## 2. Permisos Android

En Ajustes del sistema → Apps → Termux / Termux:API:

- Ubicación (necesaria para escaneo Wi‑Fi en Android 6+)
- Red / Wi‑Fi cercanas (Android 13+)
- Notificaciones (si usas `termux-notification` / pushes)

El escaneo de redes cercanas es **pasivo**: solo lee lo que el SO reporta
(SSID, BSSID, canal, RSSI, cifrado). Sin estos permisos, `/api/wifi/scan`
devolverá error o lista vacía. Ver `docs/ETHICS.md`.

## 3. Clonar y arrancar

```sh
cd ~
git clone https://github.com/NickPro5677/wifi-zero.git   # o tu fork
cd wifi-zero
./start_all.sh
```

Abre `http://127.0.0.1:8788` → wizard `/setup` (usuario, contraseña, bind).

## 4. Persistir `WZ_SESSION_SECRET` (imprescindible)

Sin esto, cada reinicio del proceso genera un secreto HMAC nuevo y **invalida
todas las sesiones** (tienes que volver a hacer login).

```sh
# una vez
mkdir -p ~/.wifi-zero
python3 -c "import secrets; print(secrets.token_hex(32))" > ~/.wifi-zero/session_secret
chmod 600 ~/.wifi-zero/session_secret

# en ~/.bashrc (o el script de boot):
export WZ_SESSION_SECRET="$(cat ~/.wifi-zero/session_secret)"
```

Comprueba: `echo "$WZ_SESSION_SECRET" | wc -c` debe ser ~65.

## 5. Arranque al encender (Termux:Boot)

1. Instala **Termux:Boot**.
2. Crea `~/.termux/boot/wifi-zero.sh`:

```sh
#!/data/data/com.termux/files/usr/bin/sh
# Arranca wifi-zero al encender el teléfono.
export WZ_SESSION_SECRET="$(cat "$HOME/.wifi-zero/session_secret" 2>/dev/null)"
cd "$HOME/wifi-zero" || exit 0
sleep 8
bash scripts/watchdog.sh
```

```sh
chmod +x ~/.termux/boot/wifi-zero.sh
```

El watchdog comprueba `logs/supervisor.pid` y, si hace falta, lanza
`python3 -m core` (un solo proceso).

## 6. Termux:Widget (arranque manual con un toque)

```sh
mkdir -p ~/.shortcuts
cat > ~/.shortcuts/wifi-zero <<'EOF'
#!/data/data/com.termux/files/usr/bin/sh
export WZ_SESSION_SECRET="$(cat "$HOME/.wifi-zero/session_secret" 2>/dev/null)"
cd "$HOME/wifi-zero" && bash scripts/watchdog.sh
EOF
chmod +x ~/.shortcuts/wifi-zero
```

Añade el widget de Termux en la pantalla de inicio y elige `wifi-zero`.

## 7. Checklist post-setup

| Paso | Cómo verificar |
|------|----------------|
| Paquetes | `./checks.sh` o panel → Sistema → Checks |
| OUI (nmap) | `[ok] nmap OUI db` |
| Wi‑Fi API | `[ok] termux-wifi-scaninfo` |
| Supervisor | `logs/supervisor.pid` vivo |
| Panel | `http://127.0.0.1:8788` responde |
| Sesión estable | `WZ_SESSION_SECRET` exportado |
| Bind | Preferir `127.0.0.1`; `0.0.0.0` solo en LAN de confianza (Bearer en claro) |
| PWA | Añadir a pantalla de inicio desde el navegador |

## Notas

- **Zero pip**: no hace falta `pip install`; CI y local usan `unittest` stdlib.
- Bind `0.0.0.0` expone el Bearer por HTTP en la Wi‑Fi: ver `docs/SECURITY.md`.
- Recuperación de contraseña (legado): `python3 scripts/set_password.py`.
