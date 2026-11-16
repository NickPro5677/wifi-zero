# -*- coding: utf-8 -*-
"""Autenticación del panel (F4): password hashing con scrypt + sesiones.

Es stdlib puro (hashlib.scrypt + secrets) y sin estados en disco: el token de
sesión es un HMAC firmado con una clave privada en memoria, con expiración.
"""
import hashlib
import hmac
import os
import secrets
import time
import base64

# estos parámetros se mantienen pero exponemos _scrypt como función pública
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1


def _random_salt():
    return secrets.token_bytes(16)


def hash_password(pw, salt=None):
    """Devuelve 'salt_b64|hash_b64'. Si salt es None, lo genera."""
    salt = salt or _random_salt()
    h = hashlib.scrypt(pw.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R,
                       p=_SCRYPT_P, dklen=32)
    return base64.b64encode(salt).decode() + "|" + base64.b64encode(h).decode()


def verify_password(pw, stored: str) -> bool:
    try:
        salt_b64, hash_b64 = stored.split("|", 1)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
    except Exception:
        return False
    h = hashlib.scrypt(pw.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R,
                       p=_SCRYPT_P, dklen=len(expected))
    return hmac.compare_digest(h, expected)


_SESSION_SECRET = os.environ.get("WZ_SESSION_SECRET") or secrets.token_hex(32)
_SESSION_TTL = 30 * 60  # 30 min


def _b64sign(payload: bytes) -> str:
    """Firma payload ASCII. Separador NUL: el MAC binario puede contener ``.``
    (~12 % de digests), y un ``rsplit(b'.')`` rechazaba tokens válidos."""
    mac = hmac.new(_SESSION_SECRET.encode(), payload, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(payload + b"\x00" + mac).decode()


def create_token(username: str) -> str:
    body = f"{time.time():.0f}:{username}".encode()
    return _b64sign(body)


def verify_token(token: str, username: str) -> bool:
    try:
        raw = base64.urlsafe_b64decode(token.encode())
        body, mac = raw.split(b"\x00", 1)
        expected = hmac.new(_SESSION_SECRET.encode(), body, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected):
            return False
        ts, uname = body.decode().split(":", 1)
        if uname != username:
            return False
        return time.time() - int(ts) < _SESSION_TTL
    except Exception:
        return False