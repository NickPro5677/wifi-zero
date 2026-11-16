# Changelog

## [4.0.0] - PWA como plano de control
### Arquitectura
- Supervisor único (`python3 -m core` / `./start_all.sh`): posee panel HTTP y
  ciclo de vida del monitor (hilo con stop cooperativo).
- La terminal queda solo para el arranque; el día a día es el panel/PWA.

### Control plane API
- `GET/PUT /api/config` (secretos redactados), `POST /api/password`, `POST /api/setup`.
- `GET /api/control/status`, `POST /api/control/{start,stop,restart,pause,resume,scan}`.
- `POST /api/checks`, `POST /api/backup`, `GET /api/logs`, `POST /api/rules/mute`.
- `GET /export/events.csv`.

### Panel
- Wizard `/setup` (first-run), vistas **Ajustes** y **Sistema**.
- PWA: `manifest.webmanifest` + service worker (shell cache; API/SSE network-first).
- Accesibilidad: landmarks, skip-link, `aria-live`, foco visible,
  `prefers-reduced-motion`, bottom nav móvil, labels en formularios.

### Motor
- `intervalos.wifi` independiente del ciclo LAN.
- Conflictos IP: `read_neighbors` acumula varias MAC por IP.
- Downgrade de cifrado en APs **existentes** (`prev_encryption` antes del upsert).
- `muted_rules` en config + UI para silenciar reglas.

### Deprecación
- `scripts/set_password.py` y edición manual de config: legado (preferir panel).
- `checks.sh` / `backup.sh` siguen; equivalentes en API/panel.

## [3.1.0] - panel v3.1 + correcciones de motor
### Correcciones
- SSE no recibía eventos del monitor (otro proceso): bomba que lee SQLite y reemite.
- Fuga de colas SSE al desconectar el cliente.
- `threat._cfg` ignoraba `config.Config` → los pesos de `config.json` no se aplicaban.
- WPA3-SAE se clasificaba como OPEN si Android no ponía el literal `WPA3`.
- `battery.pause_below` estaba documentado y no pausaba el monitor.
- `/host.html` y estáticos no estaban en la allowlist de auth (401 al abrir detalle).
- `start_all.sh` hacía POST `/api/scan` sin token: ahora se acepta desde localhost.

### Optimización
- `/api/dashboard` y `/api/health` (un round-trip para el panel).
- `hosts_with_threat` agrupa puertos por IP (O(n) en vez de n×m).
- `record_scores()` inserta el histórico de riesgo en un solo commit.
- SQLite: `timeout`, `synchronous=NORMAL`, `temp_store=MEMORY`.
- Caché corta de `app.js`/`style.css`.

### Panel
- GUI nueva: sidebar, vistas (resumen, hosts, radio, topología, eventos, whitelist),
  drawer de host, toasts de alerta, heatmap de canales, atajos de teclado.

## [3.0.0] - mejora en profundidad
### Correcciones (bugs reales)
- `db.upsert_ap`: INSERT con 14 args para 13 placeholders → los APs nuevos
  nunca se guardaban (error silenciado por el monitor). Ahora persisten.
- Detección offline: era por *membresía* (`ip not in cur`, casi nunca cierto);
  ahora es por **transición de estado** (antes con línea → no visible en el ciclo).
- `battery.eco_below` e `intervalos.sv` se ignoraban: ahora activan modo eco
  real (intervalos ×2 + sin nmap -sV) y cadencia de escaneo de servicios.
- Regla `watchlist_unknown` sin cooldown (spam): se le asignó cooldown de 600s.

### Añadido
- Motor de reglas ampliado: `mac_randomized` (MAC LAA), `ip_conflict`
  (2+ MACs en una misma IP), `gateway_changed` (MITM clásico) y `ap_open`
  (AP sin cifrado).
- `threat`: scoring fino — mapa de puertos peligrosos (telnet/ftp/rdp/redis/…),
  penalización por MAC randomizada y falta de hostname; `score_ap()` para
  riesgo de puntos de acceso (OPEN, ocultos, twin, canal 13/14).
- Historial de riesgo por host: tabla `scores` (migración v3), endpoint
  `/api/hosts/<ip>/risk` y gráfico `/chart/risk.svg`.
- `db`: WAL mode + busy_timeout, índices (events/signals/ports/stations),
  `prune()` con retención configurable por tabla.
- `lan_scan`: `get_gateway()` (busca en `ip route table all`), scan configurable
  (puertos/servicios) que devuelve snapshot con conflictos y gateway.
- `wifi_track`: banda 6GHz, `channel_utilization`, flag DFS.
- Panel: gestión de whitelist (añadir/eliminar/confiar/bloquear), filtro
  "solo alertas", columna de riesgo por AP, gráfico de riesgo por host,
  SSE vía `fetch` con token en cabecera (ya no en la URL).
- Seguridad del panel: CSRF (Origin/Referer), throttling de login
  (5 fallos / 10 min → 429), cabeceras `X-Frame-Options`/`nosniff`,
  CSV escapado (RFC 4180).
- `report`: alertas del día contadas por nivel, APs abiertos, gateway detectado.

## [2.0.0] - próximo
### Añadido (F0-F5)
- F0: configuración centralizada en `config.json` (validada), logging con
  rotación diaria, migraciones versionadas SQLite, tests unitarios con mocks
  y Makefile.
- F1: modelo de datos ampliado — `hosts_history`, `signals`, `stations`,
  `networks` y `whitelist`; parseo de `capabilities` (cifrado WPA2/WPA3,
  cipher, bandwidth, SSID oculto) y telemetría de enlace (`connectioninfo`).
- F2: motor de reglas con cooldown por entidad (new_host, mac_change/spoofing,
  offline, new_ap/rogue, downgrade de cifrado, evil-twin por SSID duplicado,
  new_port), threat scoring 0-100, whitelist de dispositivos y watchlist de
  críticos.
- F3: nmap -sV (versión de servicios) sobre puertos abiertos y scripts NSE
  broadcast (DNS-SD / SSDP) — ambos sin root.
- F4: panel web protegido con login (scrypt, stdlib), detalle por host,
  gráficos SVG, vista de radio (canales y bandas) y exportación.
- F5: monitor battery-aware (pausa si <XX% y desenchufado) y gating por
  `supplicant_state`; watchdog, backup SQLite, push ntfy/Telegram opcional.

## [1.0.0] - primera entrega
- Escáner LAN (ARP del kernel + TCP sweep) sin root, análisis WiFi vía API,
  eventos básicos, panel sin auth, notificaciones termux.
