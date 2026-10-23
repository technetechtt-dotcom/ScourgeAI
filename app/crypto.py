"""Envelope encryption for MFA secrets. The database stores ciphertext only."""
from __future__ import annotations

import base64
import hashlib
import os
import secrets

from cryptography.fernet import Fernet, InvalidToken

PREFIX = "enc:v1:"


def _material() -> str:
    configured = os.environ.get("TIC_DATA_KEY", "").strip()
    if configured:
        return configured
    if os.environ.get("TIC_ENV", "development") == "production":
        raise RuntimeError("TIC_DATA_KEY is required when TIC_ENV=production")
    path = os.environ.get("TIC_DATA_KEY_FILE", ".tic_data_key")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip()
    generated = secrets.token_urlsafe(32)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(generated)
    return generated


def _fernet() -> Fernet:
    digest = hashlib.sha256(_material().encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def seal(plaintext: str) -> str:
    return PREFIX + _fernet().encrypt(plaintext.encode()).decode("ascii")


def open_secret(stored: str | None) -> str:
    if not stored:
        return ""
    if not stored.startswith(PREFIX):
        return stored
    try:
        return _fernet().decrypt(stored[len(PREFIX) :].encode("ascii")).decode()
    except InvalidToken:
        return ""
