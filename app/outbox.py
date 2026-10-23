"""Transactional outbox. Workers claim rows so two processes do not handle the same event.

Nothing in this module dispatches responders or commands a vehicle.
"""
from __future__ import annotations

import uuid
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .accounts import aware
from .models import DeadLetter, Outbox, now

MAX_ATTEMPTS = 5
CLAIM_TIMEOUT = timedelta(seconds=30)


def requeue_dead(db: Session, tenant_id: str) -> int:
    """Return dead rows to pending. This does not deliver them or contact an external system."""
    rows = list(db.scalars(select(Outbox).where(Outbox.tenant_id == tenant_id, Outbox.status == "DEAD")))
    for row in rows:
        row.status = "PENDING"
        row.attempts = 0
        row.last_error = None
        row.processed_at = None
        row.claimed_by = None
        row.claimed_at = None
    return len(rows)


def enqueue(db: Session, tenant_id: str, topic: str, payload: dict, idempotency_key: str) -> Outbox | None:
    existing = db.scalar(select(Outbox).where(Outbox.idempotency_key == idempotency_key))
    if existing:
        return None
    row = Outbox(
        id=uuid.uuid4().hex,
        tenant_id=tenant_id,
        topic=topic,
        payload=payload,
        status="PENDING",
        attempts=0,
        idempotency_key=idempotency_key,
    )
    db.add(row)
    return row


def _handle(row: Outbox) -> None:
    payload = row.payload or {}
    if payload.get("fail"):
        raise RuntimeError("forced failure")
    if row.topic != "event.ingested":
        raise RuntimeError("unknown topic")
    if "incident_id" not in payload:
        raise RuntimeError("missing incident_id")


def _release_stale(db: Session) -> None:
    cutoff = now() - CLAIM_TIMEOUT
    claimed = list(db.scalars(select(Outbox).where(Outbox.status == "CLAIMED")))
    for row in claimed:
        if row.claimed_at is None or aware(row.claimed_at) <= cutoff:
            row.status = "PENDING"
            row.claimed_by = None
            row.claimed_at = None


def claim_pending(db: Session, worker_id: str, limit: int = 50) -> list[Outbox]:
    _release_stale(db)
    query = select(Outbox).where(Outbox.status == "PENDING").order_by(Outbox.created_at).limit(limit)
    if db.get_bind().dialect.name == "postgresql":
        query = query.with_for_update(skip_locked=True)
    rows = list(db.scalars(query))
    moment = now()
    for row in rows:
        row.status = "CLAIMED"
        row.claimed_by = worker_id
        row.claimed_at = moment
    db.flush()
    return rows


def process_outbox(db: Session, limit: int = 50, worker_id: str = "local") -> dict:
    rows = claim_pending(db, worker_id, limit)
    processed = 0
    dead = 0
    for row in rows:
        try:
            _handle(row)
        except Exception as exc:
            row.attempts += 1
            row.last_error = str(exc)[:500]
            row.claimed_by = None
            row.claimed_at = None
            if row.attempts >= MAX_ATTEMPTS:
                row.status = "DEAD"
                db.add(
                    DeadLetter(
                        id=uuid.uuid4().hex,
                        outbox_id=row.id,
                        tenant_id=row.tenant_id,
                        topic=row.topic,
                        payload=row.payload,
                        error=row.last_error,
                    )
                )
                dead += 1
            else:
                row.status = "PENDING"
            continue
        row.attempts += 1
        row.status = "PROCESSED"
        row.processed_at = now()
        row.claimed_by = None
        row.claimed_at = None
        row.last_error = None
        processed += 1
    db.commit()
    return {"processed": processed, "dead": dead, "external_dispatch": False, "worker_id": worker_id}
