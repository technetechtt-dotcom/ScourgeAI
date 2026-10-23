"""Optional OIDC-style bearer tokens. HS256 only, and only when TIC_OIDC_HMAC_SECRET is set.

This does not contact an identity provider. A deployment supplies the shared signing
secret, issuer, and audience. Session tokens are unchanged.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + padding)


def issue_token(claims: dict, secret: str) -> str:
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64(json.dumps(claims, separators=(",", ":")).encode())
    signing = f"{header}.{payload}".encode()
    signature = _b64(hmac.new(secret.encode(), signing, hashlib.sha256).digest())
    return f"{header}.{payload}.{signature}"


def verify_token(token: str) -> dict | None:
    secret = os.environ.get("TIC_OIDC_HMAC_SECRET", "").strip()
    if not secret or token.count(".") != 2:
        return None
    header_b64, payload_b64, signature_b64 = token.split(".")
    expected = _b64(hmac.new(secret.encode(), f"{header_b64}.{payload_b64}".encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(expected, signature_b64):
        return None
    try:
        header = json.loads(_unb64(header_b64))
        claims = json.loads(_unb64(payload_b64))
    except (ValueError, json.JSONDecodeError):
        return None
    if header.get("alg") != "HS256":
        return None
    issuer = os.environ.get("TIC_OIDC_ISSUER", "").strip()
    audience = os.environ.get("TIC_OIDC_AUDIENCE", "").strip()
    if issuer and claims.get("iss") != issuer:
        return None
    if audience and claims.get("aud") != audience:
        return None
    expiry = claims.get("exp")
    if not isinstance(expiry, int) or expiry < int(time.time()):
        return None
    return claims
