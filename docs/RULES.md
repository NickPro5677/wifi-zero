# Reglas de detección

Motor en `core/rules.py`. Cada regla tiene un **cooldown** (segundos) por
entidad (IP/MAC/BSSID), para evitar saturar de eventos.

| Regla | Nivel | Cooldown | Detecta |
|---|---|---|---|
| `new_host` | warn/crit | 60 s | Host nuevo en la red. `crit` si su MAC está en whitelist como no-confiable. |
| `mac_change` | crit | 300 s | La misma IP responde ahora con otra MAC (posible spoofing ARP). |
| `offline` | info | 600 s | Host conocido deja de verse. |
| `watchlist_down` | crit | 300 s | Un dispositivo marcado como crítico desaparece. |
| `new_ap` | warn | 900 s | Nuevo router visible cerca (posible rogue AP). |
| `ap_encryption_downgrade` | crit | 1800 s | Un AP rebaja su cifrado (WPA3→WPA2, WPA2→OPEN). |
| `ap_twin` | warn | 360 s | Mismo SSID con varias BSSIDs (posible evil-twin). |
| `new_port` | warn | 300 s | Un host abrió un puerto que no tenía. |
| `ap_released` | info | 120 s | El teléfono salió del WiFi (scan en pausa). |

## Cómo autorizar (whitelist/watchlist)

`config.json`:

```json
{
  "watchlist": [
    {"mac": "04:56:65:2f:f7:a0", "label": "Router"}
  ]
}
```

Desde el panel: `POST /api/whitelist` con `{mac, label, trusted}`. Los hosts
confiables no generan `new_host` crítico; los no confiables lo generan como `crit`.

## Cooldown

El cooldown evita spam: para la misma entidad y regla, depende de `COOLDOWNS`
en `core/rules.py`. Se puede tunear sin tocar código editando el diccionario
(al recargar el módulo).