"""Event ingestion. An explicit SOS is committed even when scoring fails."""
from __future__ import annotations

import hashlib
import os
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import auditlog, devices, engine, outbox
from .accounts import ensure_organisation
from .adapters import validate_adapter
from .agents import run_for_ingest
from .agents.base import SAFE_RECOMMENDATIONS
from .correlation import correlate_guardian
from .metrics import increment
from .models import Assessment, Event, EventNonce, Evidence, Incident, Recommendation
from .schemas import EventIn
from .security import authenticate_client, enforce_database_rate_limit, verify_device_signature
from .vehicle import classify_event, summarise

RULE_VERSION = "rules-v0.1"


def _new_id() -> str:
    return uuid.uuid4().hex


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def ingest_event(
    db: Session,
    body: bytes,
    *,
    timestamp: str | None,
    signature: str | None,
    nonce: str | None,
    device_key_id: str | None,
    device_signature: str | None,
    sequence: str | None,
    client_host: str,
) -> dict:
    if len(body) > 65536:
        raise HTTPException(413, "Event too large")
    try:
        event = EventIn.model_validate_json(body)
    except Exception as exc:
        raise HTTPException(422, "Invalid event schema") from exc
    enforce_database_rate_limit(db, f"{client_host}:{event.tenant_id}:{event.source_product}")
    authenticate_client(body, event.tenant_id, event.source_product, timestamp, signature)
    if not validate_adapter(event):
        raise HTTPException(422, "Unsupported product event type")
    managed_secret = None
    credential = None
    if device_key_id:
        managed_secret, credential = devices.managed_device_secret(
            db, device_key_id, event.tenant_id, event.source_product
        )
    device_verified = verify_device_signature(
        body,
        event.tenant_id,
        event.source_product,
        device_key_id,
        device_signature,
        managed_secret=managed_secret,
    )
    if event.source.signature_verified and not device_verified:
        raise HTTPException(422, "Invalid provenance claim")
    existing = db.get(Event, event.event_id)
    if existing:
        digest = hashlib.sha256(body).hexdigest()
        if (
            existing.tenant_id != event.tenant_id
            or existing.product != event.source_product
            or existing.raw_sha256 != digest
        ):
            raise HTTPException(409, "Event ID conflict")
        increment("scourgeai_events_duplicate_total")
        return {"duplicate": True, "event_id": existing.id, "incident_id": existing.incident_id}
    if not nonce or not str(nonce).strip():
        raise HTTPException(422, "Nonce required")
    production = os.environ.get("TIC_ENV", "development") == "production"
    if (production or os.environ.get("TIC_REQUIRE_DEVICE_SIGNATURE") == "1") and not device_verified:
        raise HTTPException(401, "Device signature required")
    if nonce:
        try:
            with db.begin_nested():
                db.add(
                    EventNonce(
                        id=_new_id(),
                        tenant_id=event.tenant_id,
                        product=event.source_product,
                        nonce=nonce,
                        event_id=event.event_id,
                    )
                )
        except IntegrityError as exc:
            raise HTTPException(409, "Replay detected") from exc
    if sequence and credential is None:
        raise HTTPException(422, "Sequence requires a managed device credential")
    if credential is not None:
        devices.accept_sequence(credential, sequence)
    ensure_organisation(db, event.tenant_id)
    emergency = event.event_type in engine.SOS_EVENTS
    scope = (
        Incident.tenant_id == event.tenant_id,
        Incident.product == event.source_product,
        Incident.subject_id == event.subject_id,
        Incident.status == "OPEN",
    )
    sos_open = db.scalar(
        select(Incident).where(*scope, Incident.incident_type == "EXPLICIT_SOS").order_by(Incident.created_at.desc()).limit(1)
    )
    if emergency or sos_open is not None:
        incident = sos_open or Incident(
            id=_new_id(),
            tenant_id=event.tenant_id,
            product=event.source_product,
            subject_id=event.subject_id,
            incident_type="EXPLICIT_SOS",
            severity="EMERGENCY",
        )
        created = sos_open is None
    else:
        observation = db.scalar(
            select(Incident)
            .where(*scope, Incident.incident_type == "SECURITY_OBSERVATION")
            .order_by(Incident.created_at.desc())
            .limit(1)
        )
        incident = observation or Incident(
            id=_new_id(),
            tenant_id=event.tenant_id,
            product=event.source_product,
            subject_id=event.subject_id,
            incident_type="SECURITY_OBSERVATION",
            severity="NORMAL",
        )
        created = observation is None
    if created:
        db.add(incident)
        db.flush()
    payload = event.model_dump(mode="json")
    payload["source"]["authenticated"] = device_verified
    payload["source"]["signature_verified"] = device_verified
    occurred = _aware(event.occurred_at)
    received = datetime.now(timezone.utc)
    delayed = received - occurred > timedelta(minutes=15)
    record = Event(
        id=event.event_id,
        tenant_id=event.tenant_id,
        product=event.source_product,
        event_type=event.event_type,
        subject_id=event.subject_id,
        occurred_at=event.occurred_at,
        incident_id=incident.id,
        payload=payload,
        raw_sha256=hashlib.sha256(body).hexdigest(),
        device_signature_verified=device_verified,
        delayed=delayed,
    )
    db.add(record)
    evidence = Evidence(
        id=_new_id(),
        tenant_id=event.tenant_id,
        incident_id=incident.id,
        event_id=record.id,
        sha256=record.raw_sha256,
        label=event.event_type,
    )
    db.add(evidence)
    db.flush()
    linked = list(db.scalars(select(Event).where(Event.incident_id == incident.id).order_by(Event.occurred_at)))
    degraded = False
    try:
        outcome = engine.assess(linked)
    except Exception as exc:
        degraded = True
        increment("scourgeai_assessment_failures_total")
        reason = "Risk rules were unavailable."
        outcome = engine.sos_fallback(linked, reason) if emergency else engine.degraded_fallback(linked, reason)
        auditlog.record(
            db,
            tenant_id=event.tenant_id,
            product=event.source_product,
            actor="rules-engine",
            action="ASSESSMENT_FAILED",
            subject=event.event_id,
            data={"error": type(exc).__name__, "sos_preserved": emergency},
        )
    if emergency and outcome["risk_level"] != "EMERGENCY":
        outcome = engine.sos_fallback(linked, "Rules output was refused because it was not an emergency.")
    if delayed:
        outcome["unknowns"] = list(outcome["unknowns"]) + [
            "occurred_at is materially earlier than receipt. Timing is not independently verified."
        ]
    if event.source_product == "guardian":
        notes = correlate_guardian(linked)["notes"]
        outcome["unknowns"] = list(outcome["unknowns"]) + notes
    backup_state = "NOT_APPLICABLE"
    classification = classify_event(record)
    if event.source_product == "arxvigil":
        vehicle_summary = summarise(linked)
        backup_state = vehicle_summary["backup_policy"]["state"]
        outcome["unknowns"] = list(outcome["unknowns"]) + [
            f"Vehicle data quality: {vehicle_summary['data_quality']}.",
            vehicle_summary["backup_policy"]["note"],
        ]
    incident.severity = outcome["risk_level"]
    incident.last_event_at = received
    db.add(
        Assessment(
            id=_new_id(),
            incident_id=incident.id,
            tenant_id=event.tenant_id,
            risk_level=outcome["risk_level"],
            confidence=outcome["confidence"],
            observed=outcome["observed"],
            inferred=outcome["inferred"],
            unknowns=outcome["unknowns"],
            model_version=RULE_VERSION,
        )
    )
    recommendation = None
    proposed = outcome["recommendation"]
    if proposed and proposed in SAFE_RECOMMENDATIONS:
        recommendation = db.scalar(
            select(Recommendation)
            .where(
                Recommendation.incident_id == incident.id,
                Recommendation.action == proposed,
                Recommendation.status == "PENDING",
            )
            .limit(1)
        )
        if recommendation is None:
            recommendation = Recommendation(
                id=_new_id(),
                incident_id=incident.id,
                tenant_id=event.tenant_id,
                action=proposed,
            )
            db.add(recommendation)
    elif proposed:
        auditlog.record(
            db,
            tenant_id=event.tenant_id,
            product=event.source_product,
            actor="ai_governance",
            action="RECOMMENDATION_BLOCKED",
            subject=incident.id,
            data={"action": proposed},
        )
    devices.apply_event(db, record, classification, backup_state)
    outbox.enqueue(
        db,
        event.tenant_id,
        "event.ingested",
        {
            "event_id": event.event_id,
            "incident_id": incident.id,
            "delivered_externally": False,
        },
        f"event:{event.event_id}",
    )
    auditlog.record(
        db,
        tenant_id=event.tenant_id,
        product=event.source_product,
        actor=f"client:{event.source_product}",
        action="EVENT_INGESTED",
        subject=event.event_id,
        data={"incident_id": incident.id, "rule_version": RULE_VERSION, "device_signature_verified": device_verified},
    )
    run_for_ingest(
        db,
        {
            "events": linked,
            "incident": incident,
            "outcome": outcome,
            "recommendations": [recommendation] if recommendation else [],
            "evidence": [{"event_id": evidence.event_id, "sha256": evidence.sha256}],
            "proposed_action": proposed,
        },
        event.tenant_id,
        event.source_product,
        incident.id,
    )
    db.commit()
    increment("scourgeai_events_ingested_total")
    return {
        "duplicate": False,
        "event_id": event.event_id,
        "incident_id": incident.id,
        "risk_level": outcome["risk_level"],
        "confidence": outcome["confidence"],
        "live_dispatch": False,
        "delayed": delayed,
        "device_signature_verified": device_verified,
        "assessment_degraded": degraded,
    }
