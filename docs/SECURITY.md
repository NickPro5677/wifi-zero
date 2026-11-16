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
- `panel.auth = true` + password scrypt.
- **Bind por defecto: `127.0.0.1`** (solo el teléfono). El wizard `/setup` permite elegir `0.0.0.0` (toda la LAN) de forma explícita.
- Tokens HMAC-SHA256, TTL 30 min; CSRF Origin/Referer; login throttling 5/10 min.
- `GET /api/config` **no** devuelve el hash ni el token de Telegram (redactados).
- Mutaciones (`/api/config`, `/api/password`, `/api/control/*`, `/api/backup`) requieren Bearer.
- `POST /api/scan` desde localhost sin token (compat bootstrap).
- CSV de export: no servir fuera de la LAN.

## Bind LAN y Bearer en claro

El panel habla **HTTP sin TLS**. Si `panel.bind = "0.0.0.0"`, cualquier host de
la Wi‑Fi puede ver el tráfico (incluido `Authorization: Bearer …`) con un
sniffer en la misma red.

Recomendación:

1. Deja **`127.0.0.1`** (default) y usa la PWA en el mismo dispositivo.
2. Si necesitas otro equipo en casa: preferible un túnel/reverse proxy con TLS
   (p. ej. `ssh -L` o Caddy/nginx delante) en lugar de abrir `0.0.0.0` a pelo.
3. Nunca expongas el puerto a Internet ni a Wi‑Fi de invitados/pública.

No hay TLS embebido en el proceso (stdlib + Termux: mantenemos el superficie
mínima). Documentamos el riesgo en lugar de fingir HTTPS incompleto.

## Sesiones y `WZ_SESSION_SECRET`

Sin `WZ_SESSION_SECRET` en el entorno, el secreto HMAC se genera en memoria al
arrancar → **cada reinicio invalida tokens**. Persiste el secreto:

```sh
export WZ_SESSION_SECRET="$(cat ~/.wifi-zero/session_secret)"
```

Detalle completo: `docs/INSTALL.md` (§ boot / Widget).

## Datos en reposo

- `data/wifi.db` — historial. Backup WAL-safe desde el panel (Sistema) o
  `POST /api/backup` / `make backup` (API sqlite3, no `cp` a ciegas).
- Si importa la privacidad: cifra `data/` o bórralo al salir de casa.

## Recomendaciones

- WPA2/WPA3 en tu red; OPEN = alerta.
- Whitelist de fijos; watchlist de router/NAS.
- Instala la PWA; evita operar desde redes públicas con bind `0.0.0.0`.
