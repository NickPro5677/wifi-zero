# Seguridad

## Qué hace y qué no hace wifi-zero

**Sí (permiso usuario normal, solo tu red):**
- Escaneo ARP de tu propia subred (tabla neighbor del kernel) y TCP-connect a
  servicios que tu propia red expone.
- Lectura de la API Wi-Fi de Android (redes que tu teléfono alcanza).
- Historial local de hosts/eventos en SQLite.

**No (imposible sin root y sin autorización):**
- Monitor mode, deauth, captura de paquetes de terceros, sniffing de tráfico
  ajeno, ataques activos contra dispositivos que no sean tuyos.

Usa esto **solo en redes de tu propiedad o con autorización** escrita del
dueño. El propósito documented es Blue Team / hardening de tu propio hogar.

## Modelo de amenazas del panel
- El servidor escucha en `0.0.0.0:8788`. En `config.json`:
  - `panel.auth = true` (defecto) + `panel.password` = hash scrypt generado con
    `python3 scripts/set_password.py`.
  - Para cerrojo total: `panel.bind = "127.0.0.1"`.
- La contraseña nunca se guarda en claro; solo el hash scrypt con salt.
- Los tokens de sesión son HMAC-SHA256 con secreto en `WZ_SESSION_SECRET`
  (o generado en el primer arranque) y caducan a los 30 min.
- Cualquier endpoint REST requiere `Authorization: Bearer <token>` salvo
  `/login` y `/api/login`.
- El CSV de export puede contener IPs/MACs: no lo sirvas fuera de la LAN.

## Datos en reposo
- `data/wifi.db` guarda historial (hosts, eventos, señales). Si importa la
  privacidad, cifra el directorio `data/` (por ejemplo con un archivo `.db`
  en un contenedor cifrado del sistema) o elimina periódicamente con
  `rm data/wifi.db` y vuelve a iniciar.

## Recomendaciones
- Usa la red con **WPA2/WPA3** (panel muestra cifrado de cada AP; OPEN = alerta).
- Añade a la whitelist tus dispositivos fijos para no perder visibilidad por
  alertas de "host nuevo".
- Marca router/NAS en `watchlist` para que su caída salte como crítica.