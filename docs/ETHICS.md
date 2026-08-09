# Ética y uso legítimo

wifi-zero es una **herramienta de Blue Team / monitoreo de red propia**. Su
diseño parte de dos hechos técnicos en Android sin root: no existe modo monitor
ni sniffing de terceros, y el monitor te pide **ningún** privilegio.

## Principios
1. **Red propia o autorizada.** Usa esta herramienta únicamente sobre la red
   de tu propiedad, tu laboratorio de pruebas, o con consentimiento escrito.
2. **No daña a nadie.** Los escaneos que hace son equivalentes a `ping` y
   `nmap -sV` sobre tu propia subred; no explota, no inyecta, no rompe.
3. **Transparencia.** Los vecinos cuyas redes aparecen en la vista Wi-Fi solo
   muestran información ya pública en el broadcast (SSID/BSID/canal/RSSI);
   no se cruza con tráfico de esas redes.
4. **No publicas.** No subas a Internet los datos de tu red (IPs, MACs,
   historial) salvo que sea para ti mismo. No actives `pushes` con credenciales
   al marcar alertas hacia servicios externos a menos que lo entiendas.

## Aviso legal
En la mayoría de jurisdicciones auditar una red sin permiso es ilegal incluso
si la red está en tu misma LAN. Este proyecto NO encubre eso: blueteam para tu
casa. El uso para reconofista de redes ajenas es ilegal y queda fuera de su
propósito. Todo lo que hagas con el código es bajo tu responsabilidad.

## Buenas prácticas al usarlo
- Mantén `panel.auth=true` y una contraseña fuerte (`scripts/set_password.py`).
- Si tu móvil sale de casa, detén el monitor o usa `config.json` con
  `panel.bind=127.0.0.1` para que el panel no sea visible en cafés.
- Al viajar, borra `data/wifi.db` o conservalo en cifrado si guarda detalles
  de tu red.