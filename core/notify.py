# -*- coding: utf-8 -*-
"""Notificaciones (F2/F5): termux-notification en el móvil + push opcional
(ntfy / Telegram) hacia otro dispositivo configurable en config.json."""
import os
import subprocess
import urllib.request

NOTIFY_BIN = "/data/data/com.termux/files/usr/bin/termux-notification"
LEVELS = {"info": 0, "warn": 1, "crit": 2}
LEVEL_ICONS = {"info": "ℹ", "warn": "⚠", "crit": "🚨"}


def local_push(title, msg, level="warn", channel="wifi-zero"):
    """Notificación nativa Android si termux-api está instalado."""
    if not os.path.exists(NOTIFY_BIN):
        return False
    try:
        subprocess.run(
            [NOTIFY_BIN, "-t", f"{LEVEL_ICONS.get(level,'')} {title}",
             "-c", msg, "--alert-once"],
            timeout=4, check=False,
        )
        return True
    except Exception:
        return False


def push_ntfy(url, title, msg):
    if not url:
        return False
    req = urllib.request.Request(url, data=msg.encode(),
                                 headers={"Title": title}, method="POST")
    try:
        urllib.request.urlopen(req, timeout=10)
        return True
    except Exception:
        return False


def push_telegram(token, chat, title, msg):
    if not token or not chat:
        return False
    data = f"chat_id={chat}&text={title}\n{msg}".encode()
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=10)
        return True
    except Exception:
        return False


class Notifier:
    """Callback de notificación con umbrales (usa config)."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.min = LEVELS.get(cfg.notify_min_level, 1)

    def __call__(self, rule, level, message, ip=None, mac=None, title=None):
        priority = LEVELS.get(level, 1)
        if priority < self.min:
            return
        p = self.cfg.get("pushes", default={})
        title = title or f"wifi-zero·{level} [{rule}]"
        local_push(title, message, level, self.cfg.get("notify", "channel", default="wifi-zero"))
        if p.get("enabled"):
            if p.get("ntfy_url"):
                push_ntfy(p["ntfy_url"], title, message)
            if p.get("telegram_token") and p.get("telegram_chat"):
                push_telegram(p["telegram_token"], p["telegram_chat"], title, message)