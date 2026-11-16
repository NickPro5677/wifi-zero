# -*- coding: utf-8 -*-
"""Entrypoint único: ``python3 -m core``.

Arranca el supervisor (panel HTTP + ciclo de vida del monitor).
Uso diario: abrir el panel en el navegador; no hace falta la terminal.
"""
from .supervisor import main

if __name__ == "__main__":
    raise SystemExit(main())
