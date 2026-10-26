"""Device-state projection from ingested events. Never marks backend activation."""
from __future__ import annotations

import secrets
import uuid

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .crypto import open_secret, seal
from .models import DeviceCredential, DeviceState, now


def issue_device_credential(db: Session, tenant_id: str, product: str, device_id: str) -> tuple[DeviceCredential, str]:
    existing = db.get(DeviceCredential, device_id)
    if existing is not None and existing.status == "active":
        raise HTTPException(409, "Device credential already exists")
    secret = secrets.token_urlsafe(32)
    if existing is None:
        row = DeviceCredential(
            id=device_id,
            tenant_id=tenant_id,
            product=product,
            status="active",
            secret_sealed=seal(secret),
            last_sequence=0,
        )
        db.add(row)
    else:
        row = existing
        row.tenant_id = tenant_id
        row.product = product
        row.status = "active"
        row.secret_sealed = seal(secret)
        row.last_sequence = 0
        row.revoked_at = None
        row.rotated_at = now()
    db.flush()
    return row, secret


def rotate_device_credential(db: Session, tenant_id: str, device_id: str) -> tuple[DeviceCredential, str]:
    row = db.get(DeviceCredential, device_id)
    if row is None or row.tenant_id != tenant_id:
        raise HTTPException(404, "Not found")
    if row.status != "active":
        raise HTTPException(409, "Device credential is revoked")
    secret = secrets.token_urlsafe(32)
    row.secret_sealed = seal(secret)
    row.rotated_at = now()
    db.flush()
    return row, secret


def revoke_device_credential(db: Session, tenant_id: str, device_id: str) -> DeviceCredential:
    row = db.get(DeviceCredential, device_id)
    if row is None or row.tenant_id != tenant_id:
        raise HTTPException(404, "Not found")
    row.status = "revoked"
    row.revoked_at = now()
    db.flush()
    return row


def managed_device_secret(db: Session, key_id: str, tenant_id: str, product: str) -> tuple[str | None, DeviceCredential | None]:
    row = db.get(DeviceCredential, key_id)
    if row is None:
        return None, None
    if row.tenant_id != tenant_id or row.product != product:
        raise HTTPException(401, "Device key is not valid for this tenant")
    if row.status != "active":
        raise HTTPException(401, "Device credential revoked")
    return open_secret(row.secret_sealed), row


def accept_sequence(row: DeviceCredential, sequence: str | None) -> None:
    if sequence is None:
        return
    try:
        value = int(sequence)
    except ValueError as exc:
        raise HTTPException(422, "Malformed event sequence") from exc
    if value <= int(row.last_sequence or 0):
        raise HTTPException(409, "Sequence replay")
    row.last_sequence = value


def device_id_from(event) -> str | None:
    payload = event.payload or {}
    source = payload.get("source") or {}
    observation = payload.get("observation") or {}
    for value in (source.get("device_id"), observation.get("device_id")):
        if isinstance(value, str) and value:
            return value
    return None


def apply_event(db: Session, event, classification: str, backup_state: str) -> DeviceState | None:
    device_id = device_id_from(event)
    if not device_id:
        return None
    row = db.scalar(
        select(DeviceState).where(
            DeviceState.tenant_id == event.tenant_id,
            DeviceState.product == event.product,
            DeviceState.device_id == device_id,
        )
    )
    if row is None:
        row = DeviceState(
            id=uuid.uuid4().hex,
            tenant_id=event.tenant_id,
            product=event.product,
            device_id=device_id,
            subject_id=event.subject_id,
            last_event_type=event.event_type,
            last_seen_at=event.received_at or now(),
            activated_by_backend=False,
        )
        db.add(row)
    row.last_event_type = event.event_type
    row.last_seen_at = event.received_at or now()
    row.subject_id = event.subject_id
    row.data_quality = classification
    row.backup_observation = backup_state
    row.activated_by_backend = False
    row.updated_at = now()
    if event.event_type == "device.backup_activated":
        row.tracker_role = "secondary"
    elif event.event_type == "device.primary_signal_lost":
        row.tracker_role = "primary"
    elif event.event_type == "device.jsghost.status":
        row.tracker_role = "ghost"
    elif event.event_type == "device.jseed.witness":
        row.tracker_role = "seed"
    elif event.event_type == "device.jscore.telemetry":
        row.tracker_role = "core"
    if event.event_type == "device.power_cut":
        row.power_state = "interrupted"
    if event.event_type == "device.gnss_integrity":
        row.gnss_status = classification
    if event.event_type == "device.tamper":
        row.tamper_state = "tamper_event_received"
    db.flush()
    return row
