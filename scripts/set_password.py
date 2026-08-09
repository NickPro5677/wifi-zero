# -*- coding: utf-8 -*-
"""Helper: genera el hash scrypt de una contraseña y lo escribe en config.json.

Uso:  python3 scripts/set_password.py
(Pide la nueva contraseña por teclado y actualiza panel.password)
"""
import sys
import os
import json

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "core"))
import auth  # noqa: E402

CFG = os.path.join(BASE, "config.json")

try:
    import getpass
    pw = getpass.getpass("Nueva contraseña del panel: ")
except Exception:
    pw = input("Nueva contraseña del panel: ")

if not pw:
    print("vacía — abortado")
    sys.exit(1)

stored = auth.hash_password(pw)

with open(CFG, "r", encoding="utf-8") as f:
    cfg = json.load(f)
cfg.setdefault("panel", {})["password"] = stored
with open(CFG, "w", encoding="utf-8") as f:
    json.dump(cfg, f, indent=2, ensure_ascii=False)
    f.write("\n")

print("password actualizada en config.json")