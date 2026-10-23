"""Vehicle trust and backup-tracker observation.

JamShield's 10-second backup tracker policy has to run on the device.
This module only classifies events the cloud has already received.
It never sets activated_by_backend to True.
"""
from __future__ import annotations

from datetime import datetime, timezone

BACKUP_POLICY_SECONDS = 10
HARDWARE_EVENTS = {
    "device.power_cut",
    "device.tamper",
    "device.backup_activated",
    "device.primary_signal_lost",
    "device.interference_suspected",
    "device.gnss_integrity",
    "device.jscore.telemetry",
    "device.jsghost.status",
    "device.jseed.witness",
    "vehicle.unauthorized_movement",
    "vehicle.position_divergence",
}


def _observation(event) -> dict:
    payload = getattr(event, "payload", None)
    if isinstance(payload, dict) and isinstance(payload.get("observation"), dict):
        return payload["observation"]
    observation = getattr(event, "observation", None)
    return observation if isinstance(observation, dict) else {}


def _verified(event) -> bool:
    if getattr(event, "device_signature_verified", False):
        return True
    payload = getattr(event, "payload", None)
    if isinstance(payload, dict):
        source = payload.get("source") or {}
        return bool(source.get("signature_verified")) and bool(source.get("authenticated"))
    return False


def classify_event(event) -> str:
    """Distinguish missing data, contradictory data, and a verified hardware claim."""
    observation = _observation(event)
    event_type = event.event_type
    if observation.get("conflict") is True or observation.get("data_quality") == "contradictory":
        return "contradictory"
    if event_type == "device.gnss_integrity" and "anomaly" not in observation and "fix" not in observation:
        return "missing"
    if event_type in HARDWARE_EVENTS and not observation and event_type == "device.jscore.telemetry":
        return "missing"
    if event_type in HARDWARE_EVENTS:
        if _verified(event):
            return "confirmed_hardware_event"
        return "unverified_client_claim"
    if not observation:
        return "missing"
    return "reported"


def overall_quality(events) -> str:
    labels = [classify_event(event) for event in events]
    if not labels:
        return "missing"
    if "contradictory" in labels:
        return "contradictory"
    if "missing" in labels and "confirmed_hardware_event" not in labels:
        return "missing"
    if labels and all(label == "confirmed_hardware_event" for label in labels):
        return "confirmed_hardware_event"
    if "confirmed_hardware_event" in labels and "unverified_client_claim" in labels:
        return "mixed"
    if "unverified_client_claim" in labels:
        return "unverified_client_claim"
    return labels[-1]


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def evaluate_backup_policy(events, at: datetime | None = None) -> dict:
    """Report whether a device said the backup tracker activated. Do not activate it."""
    moment = at or datetime.now(timezone.utc)
    loss = [event for event in events if event.event_type == "device.primary_signal_lost"]
    backup = [event for event in events if event.event_type == "device.backup_activated"]
    base = {
        "policy_seconds": BACKUP_POLICY_SECONDS,
        "activated_by_backend": False,
        "local_hardware_must_execute": True,
    }
    if not loss:
        return {**base, "state": "NOT_APPLICABLE", "note": "No primary tracker loss is in this record."}
    if backup:
        return {
            **base,
            "state": "CONFIRMED_BY_DEVICE_EVENT",
            "note": "A device event reported backup tracker activation. This service did not command it.",
            "source_event_ids": [event.id for event in backup],
        }
    oldest = min(_as_utc(event.occurred_at) for event in loss)
    elapsed = (moment - oldest).total_seconds()
    if elapsed >= BACKUP_POLICY_SECONDS:
        return {
            **base,
            "state": "NOT_OBSERVED",
            "elapsed_seconds": elapsed,
            "note": "The backup tracker event is missing. Absence is not a cloud command to activate hardware.",
        }
    return {
        **base,
        "state": "PENDING_OBSERVATION",
        "elapsed_seconds": elapsed,
        "note": "Inside the hardware policy window. The cloud is waiting for a device report.",
    }


def summarise(events, at: datetime | None = None) -> dict:
    policy = evaluate_backup_policy(events, at=at)
    return {
        "data_quality": overall_quality(events),
        "per_event": [{"event_id": event.id, "event_type": event.event_type, "quality": classify_event(event)} for event in events],
        "backup_policy": policy,
        "theft_confirmed": False,
        "immobilisation": "not_available",
    }
