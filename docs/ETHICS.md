# Ética y uso legítimo

wifi-zero es una **herramienta de Blue Team / monitoreo de red propia**.
Sin root no hay modo monitor ni sniffing de terceros; el monitor no pide
privilegios elevados.

## Principios
1. **Red propia o autorizada.** Usa esta herramienta únicamente sobre la red
   de tu propiedad, tu laboratorio de pruebas, o con consentimiento escrito.
2. **No daña a nadie.** Los escaneos que hace son equivalentes a `ping` y
   `nmap -sV` sobre tu propia subred; no explota, no inyecta, no rompe.
3. **Transparencia.** Los vecinos cuyas redes aparecen en la vista Wi-Fi (si
   usas el escaneo opcional) solo muestran información ya pública en el
   broadcast (SSID/BSSID/canal/RSSI); no se cruza con tráfico de esas redes.
4. **No publicas.** No subas a Internet los datos de tu red (IPs, MACs,
   historial) salvo que sea para ti mismo. No actives `pushes` con credenciales
   al marcar alertas hacia servicios externos a menos que lo entiendas.

## Escaneo Wi‑Fi cercano (pasivo / opcional)

`GET|POST /api/wifi/scan` y la vista **Radio → Escanear cercanas** usan
`termux-wifi-scaninfo` (Termux:API) cuando está disponible: el mismo resultado
que Android muestra al listar redes. Campos: SSID, BSSID, frecuencia/canal,
RSSI, capabilities/cifrado y timestamp si el sistema lo incluye.

- En el modelo **híbrido (Pi + PWA)** este escaneo es **secundario**. El
  inventario principal es ARP/LAN en el Pi; falta de Termux:API **no** es un
  fallo duro del monitor.
- **No** hay modo monitor, captura de handshakes, deauth, spoofing de MAC
  ni ataques a contraseñas.
- En Android 6+ hace falta **permiso de ubicación**; en Android 13+ también
  **Wi‑Fi cercanas**, concedidos a Termux:API (solo si aún usas ese camino).

## Aviso legal
En la mayoría de jurisdicciones auditar una red sin permiso es ilegal incluso
si la red está en tu misma LAN. Este proyecto NO encubre eso: blueteam para tu
casa. El uso para reconofista de redes ajenas es ilegal y queda fuera de su
propósito. Todo lo que hagas con el código es bajo tu responsabilidad.

## Buenas prácticas al usarlo
- Mantén `panel.auth=true` y una contraseña fuerte.
- Con bind `0.0.0.0` (Pi + PWA), limítate a LAN de confianza.
- Al viajar, borra `data/wifi.db` o consérvalo cifrado si guarda detalles
  de tu red.
