"""Client HMAC, device-key checks, and an in-process rate limiter.

The rate limiter is per process. It is not a substitute for an edge limiter
when more than one API process is running.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from collections import defaultdict, deque

from fastapi import HTTPException


def client_secrets() -> dict[str, str]:
    raw = os.environ.get("TIC_CLIENT_SECRETS", "{}")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Invalid TIC_CLIENT_SECRETS JSON") from exc
    if not isinstance(data, dict):
        raise RuntimeError("TIC_CLIENT_SECRETS must be a JSON object")
    return {str(key): str(value) for key, value in data.items()}


def device_keys() -> dict[str, dict]:
    raw = os.environ.get("TIC_DEVICE_KEYS", "{}")
    try:
        data = json.loads(raw or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError("Invalid TIC_DEVICE_KEYS JSON") from exc
    return data if isinstance(data, dict) else {}


def safe_compare(expected: str, presented: str) -> bool:
    if not isinstance(expected, str) or not isinstance(presented, str):
        return False
    return hmac.compare_digest(expected, presented)


def authenticate_client(body: bytes, tenant: str, product: str, timestamp: str | None, signature: str | None) -> None:
    secret = client_secrets().get(f"{tenant}:{product}")
    if not secret or not timestamp or not signature:
        raise HTTPException(401, "Missing or invalid authentication")
    try:
        ts = int(timestamp)
        if abs(time.time() - ts) > 300:
            raise ValueError("stale")
    except ValueError as exc:
        raise HTTPException(401, "Stale or malformed timestamp") from exc
    expected = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    if not safe_compare(expected, signature):
        raise HTTPException(401, "Invalid signature")


def verify_device_signature(
    body: bytes,
    tenant: str,
    product: str,
    key_id: str | None,
    signature: str | None,
) -> bool:
    """Return True only when a configured device key matches this exact body."""
    if not key_id and not signature:
        return False
    if not key_id or not signature:
        raise HTTPException(401, "Incomplete device signature")
    record = device_keys().get(key_id)
    if not isinstance(record, dict):
        raise HTTPException(401, "Unknown device key")
    if record.get("tenant_id") != tenant or record.get("product") != product:
        raise HTTPException(401, "Device key is not valid for this tenant")
    secret = record.get("secret")
    if not isinstance(secret, str) or not secret:
        raise HTTPException(401, "Unknown device key")
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    if not safe_compare(expected, signature):
        raise HTTPException(401, "Invalid device signature")
    return True


class RateLimiter:
    def __init__(self, limit: int, window_seconds: int):
        self.limit = limit
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.time()
        bucket = self._hits[key]
        while bucket and now - bucket[0] > self.window_seconds:
            bucket.popleft()
        if len(bucket) >= self.limit:
            return False
        bucket.append(now)
        return True


def _default_limiter() -> RateLimiter:
    return RateLimiter(
        int(os.environ.get("TIC_RATE_LIMIT", "600")),
        int(os.environ.get("TIC_RATE_WINDOW", "60")),
    )


limiter = _default_limiter()


def enforce_rate_limit(key: str) -> None:
    """In-memory limiter kept for unit tests. Request handling uses allow_database."""
    if not limiter.allow(key):
        raise HTTPException(429, "Rate limit exceeded")


_DEV_SECRET_MARKERS = (
    "development-change-me",
    "development-change-me-too",
    "replace-with-a-long-random",
    "replace-me",
    "correct-horse-battery",
)


def assert_production_configuration() -> None:
    """Refuse to boot production with placeholder secrets or optional device trust."""
    if os.environ.get("TIC_ENV", "development") != "production":
        return
    if not os.environ.get("TIC_DATA_KEY", "").strip():
        raise RuntimeError("TIC_DATA_KEY is required when TIC_ENV=production")
    if os.environ.get("TIC_REQUIRE_DEVICE_SIGNATURE", "1") != "1":
        raise RuntimeError("Device signatures are required when TIC_ENV=production")
    secrets = client_secrets()
    if not secrets:
        raise RuntimeError("TIC_CLIENT_SECRETS is required when TIC_ENV=production")
    for secret in secrets.values():
        lowered = secret.lower()
        if len(secret) < 24 or any(marker in lowered for marker in _DEV_SECRET_MARKERS):
            raise RuntimeError("Production client secrets must replace the development placeholders")


def allow_database(db, key: str, limit: int | None = None, window: int | None = None) -> bool:
    """Shared counter. A second process reading the same database sees the same window."""
    from datetime import timedelta

    from sqlalchemy import select

    from .accounts import aware
    from .models import RateBucket, now

    limit = int(os.environ.get("TIC_RATE_LIMIT", "600") if limit is None else limit)
    window = int(os.environ.get("TIC_RATE_WINDOW", "60") if window is None else window)
    current = now()
    query = select(RateBucket).where(RateBucket.key == key)
    if db.get_bind().dialect.name == "postgresql":
        query = query.with_for_update()
    row = db.scalar(query)
    if row is None or aware(row.window_start) <= current - timedelta(seconds=window):
        if row is None:
            db.add(RateBucket(key=key, window_start=current, hits=1))
        else:
            row.window_start = current
            row.hits = 1
        db.flush()
        return True
    if row.hits >= limit:
        return False
    row.hits += 1
    db.flush()
    return True


def enforce_database_rate_limit(db, key: str) -> None:
    allowed = allow_database(db, key)
    db.commit()
    if not allowed:
        raise HTTPException(429, "Rate limit exceeded")
