"""Device-state projection from ingested events. Never marks backend activation."""
from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import DeviceState, now


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
