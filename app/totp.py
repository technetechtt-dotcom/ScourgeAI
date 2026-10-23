"""RFC 6238 TOTP (SHA-1, 30-second step, 6 digits) for privileged user MFA."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time


def random_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def totp_code(secret: str, at: float | None = None, step: int = 30, digits: int = 6) -> str:
    padded = secret.upper() + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded, casefold=True)
    counter = int((time.time() if at is None else at) // step)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10**digits)).zfill(digits)


def verify_totp(secret: str, code: str | None, window: int = 1) -> bool:
    if not code or not code.isdigit() or len(code) != 6:
        return False
    now = time.time()
    for shift in range(-window, window + 1):
        if hmac.compare_digest(totp_code(secret, at=now + shift * 30), code):
            return True
    return False
