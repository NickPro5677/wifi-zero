# -*- coding: utf-8 -*-
"""Reporte diario Markdown (F5/F6): run manual o programado.

Uso: python3 -m core.report [--csv]
Genera data/reports/resumen-YYYY-MM-DD.md con el estado de la red.
"""
import os
import sys
import time

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "core"))
import db  # noqa: E402


def main():
    con = db.connect()
    st = db.stats(con)
    hosts = db.hosts_with_threat(con, None, None)
    events = db.all_events(con, 500)
    now = time.strftime("%d/%m/%Y %H:%M")
    lines = [f"# Resumen wifi-zero · {now}",
             "",
             f"- Hosts: {st['hosts']} (online {st['up']})",
             f"- APs visibles: {st['aps']}",
             f"- Eventos totales: {st['events']}",
             f"- Puertos en uso: {st['port_ips']}",
             "",
             "## Riesgo por host",
             "| IP | MAC | Fabricante | Riesgo | Nivel |",
             "|---|-----|-----------|:-----:|-------|"]
    for h in hosts:
        lines.append(f"| {h['ip']} | {h.get('mac') or '—'} | {h.get('vendor') or '?'} | "
                     f"{h['score']} | {h['tier']} |")
    lines += ["", "## Últimos eventos (20)", ""]
    for e in events[-20:]:
        ts = time.strftime("%d/%m %H:%M", time.localtime(e['ts']))
        lines.append(f"- `{ts}` **{e['level']}** · {e['message']}")
    os.makedirs(os.path.join(BASE, "data", "reports"), exist_ok=True)
    out = os.path.join(BASE, "data", "reports",
                       f"resumen-{time.strftime('%Y-%m-%d')}.md")
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"reporte: {out}")
    con.close()


if __name__ == "__main__":
    main()