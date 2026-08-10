# -*- coding: utf-8 -*-
"""Reporte diario Markdown (F5/F6): run manual o programado.

Uso: python3 -m core.report [hoy|ayer]
Genera data/reports/resumen-YYYY-MM-DD.md con el estado de la red:
inventario, riesgo, alertas del día, APs, gateway y tendencias.
"""
import os
import sys
import time

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "core"))
import db  # noqa: E402


def main():
    day = sys.argv[1] if len(sys.argv) > 1 else "hoy"
    con = db.connect()
    st = db.stats(con)
    hosts = db.hosts_with_threat(con, None, None)
    events = db.all_events(con, 1000)
    aps = db.all_aps(con)
    now = time.strftime("%d/%m/%Y %H:%M")

    today0 = int(time.mktime(time.strptime(time.strftime("%Y-%m-%d"), "%Y-%m-%d")))
    if day == "ayer":
        today0 -= 86400
    today_ev = [e for e in events if e["ts"] >= today0]
    warn = [e for e in today_ev if e["level"] == "warn"]
    crit = [e for e in today_ev if e["level"] == "crit"]
    open_aps = [a for a in aps if (a.get("encryption") or "").upper() in ("", "OPEN", "WEP")]
    gateways = con.execute(
        "SELECT info FROM runs WHERE kind='gateway' ORDER BY id DESC LIMIT 1").fetchone()

    lines = [f"# Resumen wifi-zero · {now}",
             "",
             f"- Hosts: {st['hosts']} (online {st['up']})",
             f"- APs visibles: {st['aps']} ({len(open_aps)} sin cifrar o débiles)",
             f"- Eventos hoy: {len(today_ev)} (⚠ {len(warn)} · 🚨 {len(crit)})",
             f"- Puertos en uso: {st['port_ips']}",
             f"- Gateway: {gateways['info'] if gateways else 'no detectado'}",
             f"- Schema: v{st['version']}",
             "",
             "## Riesgo por host",
             "| IP | MAC | Fabricante | Riesgo | Nivel |",
             "|---|-----|-----------|:-----:|-------|"]
    for h in hosts:
        lines.append(f"| {h['ip']} | {h.get('mac') or '—'} | {h.get('vendor') or '?'} | "
                     f"{h['score']} | {h['tier']} |")
    if open_aps:
        lines += ["", "## APs abiertos o con cifrado débil", "",
                  "| SSID | BSSID | Canal | RSSI |", "|------|-------|:-----:|:----:|"]
        for a in open_aps[:10]:
            lines.append(f"| {a.get('ssid') or '<oculto>'} | {a.get('bssid')} | "
                         f"{a.get('channel') or '—'} | {a.get('rssi') or '—'} |")
    lines += ["", f"## Alertas del día ({len(today_ev)})", ""]
    if today_ev:
        for e in today_ev[-30:]:
            ts = time.strftime("%d/%m %H:%M", time.localtime(e['ts']))
            lines.append(f"- `{ts}` **{e['level']}** · {e['message']}")
    else:
        lines.append("- sin eventos hoy (red tranquila)")
    os.makedirs(os.path.join(BASE, "data", "reports"), exist_ok=True)
    out = os.path.join(BASE, "data", "reports",
                       f"resumen-{time.strftime('%Y-%m-%d')}.md")
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"reporte: {out}")
    con.close()


if __name__ == "__main__":
    main()