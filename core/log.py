# -*- coding: utf-8 -*-
"""Logging wifi-zero: rotación diaria a logs/*.log + consola opcional."""
import logging
import logging.handlers
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, "logs")


def setup(name="wifi-zero", level=logging.INFO, console=True):
    os.makedirs(LOG_DIR, exist_ok=True)
    log = logging.getLogger(name)
    if log.handlers:  # evitar duplicados si se llama dos veces
        return log
    log.setLevel(level)
    fmt = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s: %(message)s", "%H:%M:%S"
    )
    fh = logging.handlers.TimedRotatingFileHandler(
        os.path.join(LOG_DIR, "wifi-zero.log"),
        when="midnight", backupCount=7, encoding="utf-8",
    )
    fh.setFormatter(fmt)
    log.addHandler(fh)
    if console:
        ch = logging.StreamHandler()
        ch.setFormatter(fmt)
        log.addHandler(ch)
    # silenciar el http.server de stdlib (no queremos su spam)
    logging.getLogger("http.server").setLevel(logging.WARNING)
    return log


def get(name="wifi-zero"):
    return logging.getLogger(name)