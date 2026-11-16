# Seguridad

## Qué hace y qué no hace wifi-zero

**Sí (permiso usuario normal, solo tu red):**
- Escaneo ARP de tu propia subred y TCP-connect a servicios de tu red.
- Lectura opcional de la API Wi-Fi de Android (Termux) si aún corres ahí.
- Historial local de hosts/eventos en SQLite.
- Control del monitor y de la config desde el panel autenticado.

**No (imposible sin root y sin autorización):**
- Monitor mode, deauth, captura de paquetes de terceros, sniffing, cracking.

Usa esto **solo en redes de tu propiedad o con autorización** escrita.

## Modelo de amenazas del panel (v4)

- Arranque: `python3 -m core` / `./start_all.sh` / systemd.
- First-run en `/setup` obliga a crear contraseña.
- `panel.auth = true` + password scrypt.
- **Bind por defecto: `127.0.0.1`**. En Pi + PWA el wizard recomienda
  `0.0.0.0` (LAN) de forma explícita.
- Tokens HMAC-SHA256, TTL 30 min; CSRF Origin/Referer; login throttling 5/10 min.
- `GET /api/config` **no** devuelve el hash ni el token de Telegram (redactados).
- Mutaciones requieren Bearer.
- `POST /api/scan` desde localhost sin token (compat bootstrap).

## Bind LAN y Bearer en claro

El panel habla **HTTP sin TLS**. Si `panel.bind = "0.0.0.0"`, cualquier host de
la Wi‑Fi puede ver el tráfico (incluido `Authorization: Bearer …`) con un
sniffer en la misma red.

Recomendación (híbrido Pi + teléfono):

1. Usa **`0.0.0.0` solo en LAN de confianza** (casa), nunca en Wi‑Fi de invitados
   ni pública.
2. Preferible un túnel/reverse proxy con TLS (`ssh -L`, Caddy/nginx) si la red
   no es de confianza absoluta.
3. Nunca expongas el puerto a Internet.
4. En Termux (legado), `127.0.0.1` sigue siendo lo más seguro si el panel solo
   se usa en el mismo dispositivo.

No hay TLS embebido en el proceso (stdlib: superficie mínima). Documentamos el
riesgo en lugar de fingir HTTPS incompleto.

## Sesiones y `WZ_SESSION_SECRET`

Sin `WZ_SESSION_SECRET` en el entorno, el secreto HMAC se genera en memoria al
arrancar → **cada reinicio invalida tokens**. Persiste el secreto:

```sh
export WZ_SESSION_SECRET="$(cat ~/.wifi-zero/session_secret)"
# o en systemd: ver deploy/wifi-zero.service
```

Detalle: `docs/INSTALL.md`.

## Datos en reposo

- `data/wifi.db` — historial. Backup WAL-safe desde el panel (Sistema) o
  `POST /api/backup` / `make backup`.
- Si importa la privacidad: cifra `data/` o bórralo al salir de casa.

## Recomendaciones

- WPA2/WPA3 en tu red; OPEN = alerta.
- Whitelist de fijos; watchlist de router/NAS.
- Instala la PWA en el teléfono; evita redes públicas con bind `0.0.0.0`.
