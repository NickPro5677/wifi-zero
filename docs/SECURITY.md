# Seguridad

## Qué hace y qué no hace wifi-zero

**Sí (permiso usuario normal, solo tu red):**
- Escaneo ARP de tu propia subred y TCP-connect a servicios de tu red.
- Lectura de la API Wi-Fi de Android (redes que tu teléfono alcanza).
- Historial local de hosts/eventos en SQLite.
- Control del monitor y de la config desde el panel autenticado.

**No (imposible sin root y sin autorización):**
- Monitor mode, deauth, captura de paquetes de terceros, sniffing.

Usa esto **solo en redes de tu propiedad o con autorización** escrita.

## Modelo de amenazas del panel (v4)
- Arranque: `python3 -m core` / `./start_all.sh`. First-run en `/setup` obliga a crear contraseña.
- `panel.auth = true` + password scrypt. Preferible `panel.bind = "127.0.0.1"`.
- Tokens HMAC-SHA256, TTL 30 min; CSRF Origin/Referer; login throttling 5/10 min.
- `GET /api/config` **no** devuelve el hash ni el token de Telegram (redactados).
- Mutaciones (`/api/config`, `/api/password`, `/api/control/*`, `/api/backup`) requieren Bearer.
- `POST /api/scan` desde localhost sin token (compat bootstrap).
- CSV de export: no servir fuera de la LAN.

## Datos en reposo
- `data/wifi.db` — historial. Backup desde el panel (Sistema) o `POST /api/backup`.
- Si importa la privacidad: cifra `data/` o bórralo al salir de casa.

## Recomendaciones
- WPA2/WPA3 en tu red; OPEN = alerta.
- Whitelist de fijos; watchlist de router/NAS.
- Instala la PWA y evita operar desde redes públicas con bind `0.0.0.0`.
