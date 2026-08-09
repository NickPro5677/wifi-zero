# Changelog

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