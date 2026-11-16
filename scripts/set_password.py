# -*- coding: utf-8 -*-
"""LEGADO: genera el hash scrypt y lo escribe en config.json.

Uso preferido (v4): panel → Ajustes → Cambiar contraseña, o el wizard /setup.
Este script queda para recuperación / automatización:

  python3 scripts/set_password.py
"""
import sys
import os
import json

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "core"))
import auth  # noqa: E402
import config as wz_config  # noqa: E402

CFG = os.path.join(BASE, "config.json")

print("(legado) Preferible: abrir el panel → Ajustes, o /setup en first-run.")
try:
    import getpass
    pw = getpass.getpass("Nueva contraseña del panel: ")
except Exception:
    pw = input("Nueva contraseña del panel: ")

if not pw:
    print("vacía — abortado")
    sys.exit(1)
if len(pw) < 6:
    print("demasiado corta (mín. 6)")
    sys.exit(1)

wz_config.save_password(pw, path=CFG)
print("password actualizada en config.json")
