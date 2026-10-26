"""HTTP API. Version 0.3 is still a prototype: it does not dispatch responders or command vehicles."""
from __future__ import annotations

import json
import os
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, StreamingResponse
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from . import auditlog, ingest
from .accounts import (
    account_locked,
    clear_login_failures,
    consume_password_reset,
    consume_recovery_code,
    create_user,
    ensure_organisation,
    issue_password_reset,
    issue_recovery_codes,
    issue_session,
    list_sessions,
    lookup_user,
    register_login_failure,
    revoke_session_id,
    revoke_token,
    revoke_user_sessions,
    update_user,
    user_for_token,
)
from .authz import Principal, require_permission, resolve_principal
from .copilot import answer_question, build_brief, handover_report
from .db import SessionLocal, db_session, engine
from .crypto import open_secret, seal
from .divergence import cross_domain_divergence
from .mtls import mtls_response
from .logging_config import configure_logging
from .metrics import render
from .models import (
    AgentExecution,
    Assessment,
    Audit,
    CrossDomainGrant,
    DeadLetter,
    DeviceState,
    Event,
    Evidence,
    Incident,
    ModelVersion,
    Outbox,
    Recommendation,
    User,
)
from .schema_compat import ensure_schema
from .outbox import requeue_dead
from .schemas import (
    GrantIn,
    LoginIn,
    MfaConfirmIn,
    ModelUpdateIn,
    PasswordResetIn,
    QuestionIn,
    ReviewIn,
    SearchIn,
    StatusIn,
    UserCreateIn,
    UserUpdateIn,
)
from .security import allow_database, assert_production_configuration
from .seed import register_model, seed_demo_accounts, seed_reference_data
from .tenancy import TenantScope
from .totp import random_secret, verify_totp
from .worker import start_worker

VERSION = "0.3.2"
HUMAN_ROLES = {"operator", "supervisor", "administrator", "developer"}
ensure_schema(engine)
configure_logging()
assert_production_configuration()


@asynccontextmanager
async def lifespan(app: FastAPI):
    with SessionLocal() as db:
        seed_reference_data(db)
        seed_demo_accounts(db)
        db.commit()
    stop = start_worker()
    yield
    if stop is not None:
        stop.set()


app = FastAPI(
    title="ScourgeAI",
    version=VERSION,
    description="Prototype only: no live emergency dispatch, no vehicle immobilisation, and no language-model actions.",
    lifespan=lifespan,
)


@app.exception_handler(RequestValidationError)
async def readable_validation_error(request: Request, exc: RequestValidationError):
    parts = []
    for err in exc.errors():
        loc = [str(part) for part in err.get("loc", []) if part != "body"]
        name = ".".join(loc) or "request"
        parts.append(f"{name}: {err.get('msg', 'invalid')}")
    return JSONResponse(status_code=422, content={"detail": "; ".join(parts)})


@app.middleware("http")
async def mtls_gate(request: Request, call_next):
    if request.url.path.startswith("/v1"):
        denied = mtls_response(request.scope)
        if denied is not None:
            return denied
    return await call_next(request)


def principal(
    tenant_id: str,
    product: str,
    db: Session = Depends(db_session),
    x_client_secret: str | None = Header(None),
    authorization: str | None = Header(None),
) -> Principal:
    return resolve_principal(db, tenant_id, product, authorization, x_client_secret)


def _id() -> str:
    return uuid.uuid4().hex


def asdict_inc(row: Incident) -> dict:
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "product": row.product,
        "subject_id": row.subject_id,
        "incident_type": row.incident_type,
        "status": row.status,
        "severity": row.severity,
        "created_at": row.created_at.isoformat(),
    }


def _load_incident_graph(db: Session, incident: Incident):
    events = list(db.scalars(select(Event).where(Event.incident_id == incident.id).order_by(Event.occurred_at, Event.id)))
    assessment = db.scalar(
        select(Assessment).where(Assessment.incident_id == incident.id).order_by(Assessment.created_at.desc()).limit(1)
    )
    recommendations = list(
        db.scalars(select(Recommendation).where(Recommendation.incident_id == incident.id).order_by(Recommendation.created_at))
    )
    return events, assessment, recommendations


@app.get("/dashboard", include_in_schema=False)
def dashboard():
    return FileResponse(
        Path(__file__).parent / "static" / "index.html",
        headers={"Cache-Control": "no-store"},
    )


@app.get("/health")
def health():
    return {"status": "ok", "service": "scourgeai", "live_dispatch": False, "version": VERSION}


@app.get("/ready")
def ready(db: Session = Depends(db_session)):
    db.execute(text("SELECT 1"))
    return {"ready": True, "live_dispatch": False}


@app.get("/metrics")
def metrics():
    return PlainTextResponse(render(), media_type="text/plain; version=0.0.4")


@app.post("/v1/events", status_code=201)
async def post_event(
    request: Request,
    db: Session = Depends(db_session),
    x_event_timestamp: str | None = Header(None),
    x_event_signature: str | None = Header(None),
    x_event_nonce: str | None = Header(None),
    x_device_key_id: str | None = Header(None),
    x_device_signature: str | None = Header(None),
):
    host = request.client.host if request.client else "unknown"
    body = await request.body()
    return ingest.ingest_event(
        db,
        body,
        timestamp=x_event_timestamp,
        signature=x_event_signature,
        nonce=x_event_nonce,
        device_key_id=x_device_key_id,
        device_signature=x_device_signature,
        client_host=host,
    )


@app.post("/v1/auth/login")
def login(body: LoginIn, request: Request, db: Session = Depends(db_session)):
    from .passwords import verify_password

    host = request.client.host if request.client else "unknown"
    attempt_key = f"login:{body.organisation_id.strip().lower()}:{body.email.strip().lower()}"
    if not allow_database(db, attempt_key, limit=10, window=900):
        db.commit()
        raise HTTPException(429, "Too many sign-in attempts. Try again later.")
    user = lookup_user(db, body.organisation_id, body.email)
    if user is None:
        db.commit()
        raise HTTPException(401, "No account matches that organisation, email, and password.")
    if account_locked(user):
        db.commit()
        raise HTTPException(423, "This account is temporarily locked.")
    if not verify_password(body.password, user.password_hash):
        register_login_failure(user)
        auditlog.record(
            db,
            tenant_id=user.organisation_id,
            actor=user.email,
            action="LOGIN_FAILED",
            subject=user.id,
            data={"client_host": host},
        )
        db.commit()
        raise HTTPException(401, "No account matches that organisation, email, and password.")
    clear_login_failures(user)
    if not user.mfa_enabled:
        token = issue_session(db, user, scope="mfa_enroll", client_host=host)
        auditlog.record(
            db,
            tenant_id=user.organisation_id,
            actor=user.email,
            action="LOGIN_MFA_ENROLL",
            subject=user.id,
            data={"role": user.role},
        )
        db.commit()
        return {
            "access_token": None,
            "enrollment_token": token,
            "mfa_enrollment_required": True,
            "mfa_required": False,
            "role": user.role,
            "organisation_id": user.organisation_id,
            "security_alert": None,
        }
    used_recovery = False
    if body.recovery_code:
        if not consume_recovery_code(user, body.recovery_code):
            register_login_failure(user)
            db.commit()
            raise HTTPException(401, "Invalid recovery code")
        used_recovery = True
    elif not verify_totp(open_secret(user.mfa_secret), body.totp):
        register_login_failure(user)
        db.commit()
        detail = "Authenticator code required." if not body.totp else "Invalid MFA code"
        raise HTTPException(401, detail)
    alert = None
    if user.last_login_host and user.last_login_host != host:
        alert = "Sign-in from a new client address."
        auditlog.record(
            db,
            tenant_id=user.organisation_id,
            actor=user.email,
            action="SUSPICIOUS_LOGIN",
            subject=user.id,
            data={"previous_host": user.last_login_host, "client_host": host},
        )
    user.last_login_host = host
    token = issue_session(db, user, scope="full", client_host=host)
    auditlog.record(
        db,
        tenant_id=user.organisation_id,
        actor=user.email,
        action="LOGIN",
        subject=user.id,
        data={"role": user.role, "mfa": True, "recovery_code": used_recovery, "client_host": host},
    )
    db.commit()
    return {
        "access_token": token,
        "enrollment_token": None,
        "mfa_enrollment_required": False,
        "mfa_required": False,
        "role": user.role,
        "organisation_id": user.organisation_id,
        "security_alert": alert,
    }


def _enrollment_user(
    db: Session,
    authorization: str | None,
) -> User:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Unauthorized")
    user = user_for_token(db, authorization.split(" ", 1)[1].strip(), scope="mfa_enroll")
    if user is None or user.role not in HUMAN_ROLES:
        raise HTTPException(401, "Unauthorized")
    return user


@app.post("/v1/auth/mfa/enroll")
def mfa_enroll(db: Session = Depends(db_session), authorization: str | None = Header(None)):
    user = _enrollment_user(db, authorization)
    secret = random_secret()
    user.mfa_secret = seal(secret)
    user.mfa_enabled = False
    db.commit()
    issuer = os.environ.get("TIC_MFA_ISSUER", "ScourgeAI")
    return {
        "secret": secret,
        "otpauth_uri": f"otpauth://totp/{issuer}:{user.email}?secret={secret}&issuer={issuer}&digits=6&period=30",
        "mfa_enabled": False,
    }


@app.post("/v1/auth/mfa/confirm")
def mfa_confirm(body: MfaConfirmIn, db: Session = Depends(db_session), authorization: str | None = Header(None)):
    user = _enrollment_user(db, authorization)
    if not user.mfa_secret or not verify_totp(open_secret(user.mfa_secret), body.code):
        raise HTTPException(401, "Invalid MFA code")
    user.mfa_enabled = True
    codes = issue_recovery_codes(user)
    raw = authorization.split(" ", 1)[1].strip() if authorization else ""
    revoke_token(db, raw)
    token = issue_session(db, user, scope="full")
    auditlog.record(
        db,
        tenant_id=user.organisation_id,
        actor=user.email,
        action="MFA_ENABLED",
        subject=user.id,
        data={"role": user.role, "recovery_codes": len(codes)},
    )
    db.commit()
    return {"access_token": token, "mfa_enabled": True, "role": user.role, "recovery_codes": codes}


@app.post("/v1/auth/logout")
def logout(
    db: Session = Depends(db_session),
    authorization: str | None = Header(None),
):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Unauthorized")
    revoke_token(db, authorization.split(" ", 1)[1].strip())
    db.commit()
    return {"revoked": True}


def _bearer(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Unauthorized")
    return authorization.split(" ", 1)[1].strip()


@app.get("/v1/auth/sessions")
def sessions(caller: Principal = Depends(principal), db: Session = Depends(db_session), authorization: str | None = Header(None)):
    if caller.user_id is None:
        raise HTTPException(403, "Forbidden")
    return list_sessions(db, caller.user_id, _bearer(authorization))


@app.post("/v1/auth/sessions/{session_id}/revoke")
def revoke_session(
    session_id: str,
    caller: Principal = Depends(principal),
    db: Session = Depends(db_session),
):
    if caller.user_id is None or not revoke_session_id(db, session_id, caller.user_id):
        raise HTTPException(404, "Not found")
    auditlog.record(
        db,
        tenant_id=caller.tenant_id,
        actor=caller.actor,
        action="SESSION_REVOKED",
        subject=session_id,
        data={},
    )
    db.commit()
    return {"revoked": True}


@app.post("/v1/auth/sessions/revoke-others")
def revoke_other_sessions(
    caller: Principal = Depends(principal),
    db: Session = Depends(db_session),
    authorization: str | None = Header(None),
):
    if caller.user_id is None:
        raise HTTPException(403, "Forbidden")
    raw = _bearer(authorization)
    import hashlib

    kept = hashlib.sha256(raw.encode()).hexdigest()
    count = revoke_user_sessions(db, caller.user_id, keep_hash=kept)
    db.commit()
    return {"revoked": count}


@app.post("/v1/auth/password/reset")
def reset_password(body: PasswordResetIn, db: Session = Depends(db_session)):
    user = consume_password_reset(db, body.token, body.password)
    if user is None:
        raise HTTPException(401, "Invalid or expired reset token")
    auditlog.record(
        db,
        tenant_id=user.organisation_id,
        actor=user.email,
        action="PASSWORD_RESET",
        subject=user.id,
        data={},
    )
    db.commit()
    return {"reset": True}


@app.get("/v1/auth/me")
def me(caller: Principal = Depends(principal)):
    return {
        "actor": caller.actor,
        "role": caller.role,
        "method": caller.method,
        "organisation_id": caller.tenant_id,
        "product": caller.product,
    }


@app.get("/v1/organisations")
def organisation(caller: Principal = Depends(principal), db: Session = Depends(db_session)):
    require_permission(caller, "records.read")
    org = ensure_organisation(db, caller.tenant_id)
    db.commit()
    return {"id": org.id, "name": org.name}


@app.get("/v1/users")
def users(caller: Principal = Depends(principal), db: Session = Depends(db_session)):
    require_permission(caller, "users.manage")
    rows = list(db.scalars(select(User).where(User.organisation_id == caller.tenant_id).order_by(User.email)))
    return [
        {"id": row.id, "email": row.email, "role": row.role, "mfa_enabled": row.mfa_enabled, "disabled": row.disabled}
        for row in rows
    ]


@app.post("/v1/users", status_code=201)
def add_user(body: UserCreateIn, caller: Principal = Depends(principal), db: Session = Depends(db_session)):
    require_permission(caller, "users.manage")
    if caller.method != "bearer":
        raise HTTPException(403, "Forbidden")
    try:
        user = create_user(db, caller.tenant_id, body.email, body.password, body.role)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    auditlog.record(
        db,
        tenant_id=caller.tenant_id,
        actor=caller.actor,
        action="USER_CREATED",
        subject=user.id,
        data={"role": user.role},
    )
    db.commit()
    return {"id": user.id, "email": user.email, "role": user.role}


@app.post("/v1/users/{user_id}")
def change_user(
    user_id: str,
    body: UserUpdateIn,
    caller: Principal = Depends(principal),
    db: Session = Depends(db_session),
):
    require_permission(caller, "users.manage")
    if caller.method != "bearer":
        raise HTTPException(403, "Forbidden")
    if body.role is None and body.disabled is None:
        raise HTTPException(422, "role or disabled is required")
    current = db.get(User, user_id)
    if current is not None and current.id == caller.user_id and (
        body.disabled is True or (body.role is not None and body.role != current.role)
    ):
        raise HTTPException(409, "This session cannot disable or change its own account.")
    try:
        user = update_user(db, caller.tenant_id, user_id, role=body.role, disabled=body.disabled)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    if user is None:
        raise HTTPException(404, "Not found")
    auditlog.record(
        db,
        tenant_id=caller.tenant_id,
        actor=caller.actor,
        action="USER_UPDATED",
        subject=user.id,
        data={"role": user.role, "disabled": user.disabled},
    )
    db.commit()
    return {"id": user.id, "email": user.email, "role": user.role, "disabled": user.disabled}


@app.post("/v1/users/{user_id}/password-reset")
def create_password_reset(
    user_id: str,
    caller: Principal = Depends(principal),
    db: Session = Depends(db_session),
):
    require_permission(caller, "users.manage")
    if caller.method != "bearer":
        raise HTTPException(403, "Forbidden")
    user = db.get(User, user_id)
    if user is None or user.organisation_id != caller.tenant_id:
        raise HTTPException(404, "Not found")
    token = issue_password_reset(db, user)
    auditlog.record(
        db,
        tenant_id=caller.tenant_id,
        actor=caller.actor,
        action="PASSWORD_RESET_ISSUED",
        subject=user.id,
        data={},
    )
    db.commit()
    return {"reset_token": token, "expires_in": 3600}


@app.get("/v1/incidents")
def incidents(caller: Principal = Depends(principal), db: Session = Depends(db_session)):
    rows = TenantScope(db, caller.tenant_id, caller.product).incidents()
    return [asdict_inc(row) for row in rows]


def _revision(db: Session, tenant_id: str, product: str) -> str:
    latest = db.scalar(
        select(func.max(Incident.last_event_at)).where(Incident.tenant_id == tenant_id, Incident.product == product)
    )
    count = db.scalar(
        select(func.count()).select_from(Incident).where(Incident.tenant_id == tenant_id, Incident.product == product)
    )
    stamp = latest.isoformat() if latest else ""
    return f"{int(count or 0)}:{stamp}"


@app.get("/v1/stream")
def stream(caller: Principal = Depends(principal), once: int = 0):
    """Server-sent events. The dashboard uses this push feed and reconnects if it drops."""

    def generate():
        previous = None
        cycles = 1 if once else 3600
        for _ in range(cycles):
            with SessionLocal() as session:
                revision = _revision(session, caller.tenant_id, caller.product)
            if revision != previous:
                payload = {
                    "revision": revision,
                    "tenant_id": caller.tenant_id,
                    "product": caller.product,
                    "live_dispatch": False,
                }
                yield f"data: {json.dumps(payload)}\n\n"
                previous = revision
            if once:
                break
            time.sleep(1)

    return StreamingResponse(generate(), media_type="text/event-stream")


@app.get("/v1/incidents/{incident_id}")
def incident_detail(incident_id: str, caller: Principal = Depends(principal), db: Session = Depends(db_session)):
    incident = TenantScope(db, caller.tenant_id, caller.product).incident(incident_id)
    if incident is None:
        raise HTTPException(404, "Not found")
    events, assessment, recommendations = _load_incident_graph(db, incident)
    return {
        "incident": asdict_inc(incident),
        "events": [{"id": event.id, "event_type": event.event_type, "occurred_at": event.occurred_at.isoformat()} for event in events],
        "assessment": None
        if assessment is None
        else {
            "risk_level": assessment.risk_level,
            "confidence": assessment.confidence,
            "observed": assessment.observed,
            "inferred": assessment.inferred,
            "unknowns": assessment.unknowns,
            "model_version": assessment.model_version,
        },
        "recommendations": [
            {"id": row.id, "action": row.action, "status": row.status, "reviewed_by": row.reviewed_by}
            for row in recommendations
        ],
    }


@app.post("/v1/incidents/{incident_id}/status")
def incident_status(
    incident_id: str,
    body: StatusIn,
    caller: Principal = Depends(principal),
    db: Session = Depends(db_session),
):
    require_permission(caller, "incidents.update")
    incident = TenantScope(db, caller.tenant_id, caller.product).incident(incident_id)
    if incident is None:
        raise HTTPException(404, "Not found")
    incident.status = body.status
    auditlog.record(
        db,
        tenant_id=caller.tenant_id,
        product=caller.product,
        actor=caller.actor,
        action="INCIDENT_STATUS",
        subject=incident.id,
        data={"status": body.status, "note": body.note},
    )
    db.commit()
    return {"id": incident.id, "status": incident.status, "action_executed": False}


@app.post("/v1/recommendations/{recommendation_id}/review")
def review(
    recommendation_id: str,
    body: ReviewIn,
    caller: Principal = Depends(principal),
    db: Session = Depends(db_session),
):
    require_permission(caller, "recommendations.review")
    row = db.get(Recommendation, recommendation_id)
    if row is None or row.tenant_id != caller.tenant_id:
        raise HTTPException(404, "Not found")
    incident = db.get(Incident, row.incident_id)
    if incident is None or incident.product != caller.product:
        raise HTTPException(404, "Not found")
    if row.status != "PENDING":
        raise HTTPException(409, "Already reviewed")
    reviewer = caller.actor
    row.status = body.status
    row.reviewed_by = reviewer
    row.review_note = body.note
    auditlog.record(
        db,
        tenant_id=caller.tenant_id,
        product=caller.product,
        actor=reviewer,
        action="RECOMMENDATION_REVIEWED",
        subject=row.id,
        data={"decision": body.status, "note": body.note, "method": caller.method},
    )
    db.commit()
    return {"id": row.id, "status": row.status, "reviewed_by": row.reviewed_by, "action_executed": False}


@app.get("/v1/incidents/{incident_id}/brief")
def incident_brief(incident_id: str, caller: Principal = Depends(principal), db: Session = Depends(db_session)):
    incident = TenantScope(db, caller.tenant_id, caller.product).incident(incident_id)
    if incident is None:
        raise HTTPException(404, "Not found")
    events, assessment, recommendations = _load_incident_graph(db, incident)
    return build_brief(incident, events, assessment, recommendations)


@app.get("/v1/incidents/{incident_id}/timeline")
def incident_timeline(incident_id: str, caller: Principal = Depends(principal), db: Session = Depends(db_session)):
    incident = TenantScope(db, caller.tenant_id, caller.product).incident(incident_id)
    if incident is None:
        raise HTTPException(404, "Not found")
    events = list(db.scalars(select(Event).where(Event.incident_id == incident.id).order_by(Event.occurred_at, Event.id)))
    return {
        "incident_id": incident.id,
        "events": [
            {
                "id": event.id,
                "type": event.event_type,
                "occurred_at": event.occurred_at.isoformat(),
                "received_at": event.received_at.isoformat() if event.received_at else None,
                "payload_sha256": event.raw_sha256,
                "delayed": bool(event.delayed),
                "device_signature_verified": bool(event.device_signature_verified),
            }
            for event in events
        ],
    }


@app.get("/v1/incidents/{incident_id}/handover")
def incident_handover(incident_id: str, caller: Principal = Depends(principal), db: Session = Depends(db_session)):
    incident = TenantScope(db, caller.tenant_id, caller.product).incident(incident_id)
    if incident is None:
        raise HTTPException(404, "Not found")
    events, assessment, recommendations = _load_incident_graph(db, incident)
    return handover_report(incident, events, assessment, recommendations)


@app.post("/v1/incidents/{incident_id}/questions")
def incident_question(
    incident_id: str,
    body: QuestionIn,
    caller: Principal = Depends(principal),
    db: Session = Depends(db_session),
):
    incident = TenantScope(db, caller.tenant_id, caller.product).incident(incident_id)
    if incident is None:
        raise HTTPException(404, "Not found")
    events, assessment, _recommendations = _load_incident_graph(db, incident)
    answer = answer_question(incident, events, assessment, body.question)
    auditlog.record(
        db,
        tenant_id=caller.tenant_id,
        product=caller.product,
        actor=caller.actor,
        action="INCIDENT_QUESTION",
        subject=incident.id,
        data={"grounded": answer["grounded"], "llm_enabled": False},
    )
    db.commit()
    return answer


@app.get("/v1/devices")
def devices(caller: Principal = Depends(principal), db: Session = Depends(db_session)):
    rows = list(
        db.scalars(
            select(DeviceState)
            .where(DeviceState.tenant_id == caller.tenant_id, DeviceState.product == caller.product)
            .order_by(DeviceState.updated_at.desc())
        )
    )
    return [
        {
            "device_id": row.device_id,
            "subject_id": row.subject_id,
            "last_event_type": row.last_event_type,
            "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None,
            "tracker_role": row.tracker_role,
            "backup_observation": row.backup_observation,
            "power_state": row.power_state,
            "gnss_status": row.gnss_status,
            "tamper_state": row.tamper_state,
            "data_quality": row.data_quality,
            "activated_by_backend": row.activated_by_backend,
        }
        for row in rows
    ]


@app.get("/v1/evidence")
def evidence(caller: Principal = Depends(principal), db: Session = Depends(db_session), incident_id: str | None = None):
    query = select(Evidence).where(Evidence.tenant_id == caller.tenant_id)
    if incident_id:
        incident = TenantScope(db, caller.tenant_id, caller.product).incident(incident_id)
        if incident is None:
            raise HTTPException(404, "Not found")
        query = query.where(Evidence.incident_id == incident.id)
    else:
        query = query.join(Incident, Incident.id == Evidence.incident_id).where(Incident.product == caller.product)
    rows = list(db.scalars(query.order_by(Evidence.created_at.desc()).limit(200)))
    return [
        {
            "id": row.id,
            "incident_id": row.incident_id,
            "event_id": row.event_id,
            "sha256": row.sha256,
            "label": row.label,
            "mutable": False,
        }
        for row in rows
    ]


@app.get("/v1/recommendations")
def recommendations(caller: Principal = Depends(principal), db: Session = Depends(db_session)):
    rows = list(
        db.scalars(
            select(Recommendation)
            .join(Incident, Incident.id == Recommendation.incident_id)
            .where(Recommendation.tenant_id == caller.tenant_id, Incident.product == caller.product)
            .order_by(Recommendation.created_at.desc())
            .limit(200)
        )
    )
    return [
        {
            "id": row.id,
            "incident_id": row.incident_id,
            "action": row.action,
            "status": row.status,
            "reviewed_by": row.reviewed_by,
        }
        for row in rows
    ]


@app.get("/v1/models")
def models(caller: Principal = Depends(principal), db: Session = Depends(db_session)):
    seed_reference_data(db)
    db.commit()
    rows = list(db.scalars(select(ModelVersion).order_by(ModelVersion.name)))
    return [
        {
            "name": row.name,
            "version": row.version,
            "kind": row.kind,
            "status": row.status,
            "description": row.description,
            "llm": row.llm,
        }
        for row in rows
    ]


@app.get("/v1/audit")
def audit(caller: Principal = Depends(principal), db: Session = Depends(db_session)):
    rows = list(
        db.scalars(
            select(Audit)
            .where(Audit.tenant_id == caller.tenant_id)
            .where((Audit.product == caller.product) | (Audit.product.is_(None)))
            .order_by(Audit.created_at.desc())
            .limit(200)
        )
    )
    return [
        {
            "id": row.id,
            "actor": row.actor,
            "action": row.action,
            "subject": row.subject,
            "product": row.product,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "data": row.data,
        }
        for row in rows
    ]


@app.get("/v1/monitoring")
def monitoring(caller: Principal = Depends(principal), db: Session = Depends(db_session)):
    pending = db.scalar(select(func.count()).select_from(Outbox).where(Outbox.tenant_id == caller.tenant_id, Outbox.status == "PENDING"))
    dead = db.scalar(select(func.count()).select_from(DeadLetter).where(DeadLetter.tenant_id == caller.tenant_id))
    db.execute(text("SELECT 1"))
    return {
        "service": "scourgeai",
        "version": VERSION,
        "live_dispatch": False,
        "llm_enabled": False,
        "worker_enabled": os.environ.get("TIC_WORKER") == "1",
        "database": "ok",
        "outbox_pending": int(pending or 0),
        "dead_letters": int(dead or 0),
        "simulated": False,
    }


@app.get("/v1/agents")
def agents(caller: Principal = Depends(principal)):
    from .agents import catalogue

    return catalogue()


@app.get("/v1/agents/executions")
def agent_executions(
    caller: Principal = Depends(principal),
    db: Session = Depends(db_session),
    incident_id: str | None = None,
):
    query = select(AgentExecution).where(
        AgentExecution.tenant_id == caller.tenant_id,
        AgentExecution.product == caller.product,
    )
    if incident_id:
        incident = TenantScope(db, caller.tenant_id, caller.product).incident(incident_id)
        if incident is None:
            raise HTTPException(404, "Not found")
        query = query.where(AgentExecution.incident_id == incident.id)
    rows = list(db.scalars(query.order_by(AgentExecution.created_at.desc()).limit(200)))
    return [
        {
            "id": row.id,
            "agent_name": row.agent_name,
            "status": row.status,
            "confidence": row.confidence,
            "uncertainty": row.uncertainty,
            "incident_id": row.incident_id,
            "error": row.error,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }
        for row in rows
    ]


@app.post("/v1/agents/search")
def agent_search(body: SearchIn, caller: Principal = Depends(principal), db: Session = Depends(db_session)):
    from .agents import execute

    events = list(
        db.scalars(
            select(Event)
            .where(Event.tenant_id == caller.tenant_id, Event.product == caller.product)
            .order_by(Event.occurred_at.desc())
            .limit(200)
        )
    )
    result = execute(
        db,
        "search_location",
        {"events": events, "query": body.query},
        tenant_id=caller.tenant_id,
        product=caller.product,
        incident_id=None,
    )
    db.commit()
    return {"status": result.status, "confidence": result.confidence, "uncertainty": result.uncertainty, "output": result.output}


@app.get("/v1/ops/summary")
def ops_summary(caller: Principal = Depends(principal), db: Session = Depends(db_session)):
    from .agents import execute

    scope = TenantScope(db, caller.tenant_id, caller.product)
    rows = scope.incidents(limit=500)
    counts = {
        "incidents": len(rows),
        "emergency": sum(1 for row in rows if row.severity == "EMERGENCY"),
        "open": sum(1 for row in rows if row.status == "OPEN"),
    }
    result = execute(
        db,
        "operations_intelligence",
        {"counts": counts, "events": []},
        tenant_id=caller.tenant_id,
        product=caller.product,
        incident_id=None,
    )
    db.commit()
    return result.output | {"confidence": result.confidence, "simulated": False}


@app.get("/v1/divergence")
def divergence(subject_id: str, caller: Principal = Depends(principal), db: Session = Depends(db_session)):
    return cross_domain_divergence(db, caller.tenant_id, subject_id)


@app.post("/v1/grants", status_code=201)
def grant(body: GrantIn, caller: Principal = Depends(principal), db: Session = Depends(db_session)):
    require_permission(caller, "users.manage")
    if body.from_product == body.to_product:
        raise HTTPException(422, "Grant must cross products")
    row = CrossDomainGrant(
        id=_id(),
        tenant_id=caller.tenant_id,
        from_product=body.from_product,
        to_product=body.to_product,
        purpose=body.purpose,
        granted_by=caller.actor,
    )
    db.add(row)
    auditlog.record(
        db,
        tenant_id=caller.tenant_id,
        product=caller.product,
        actor=caller.actor,
        action="CROSS_DOMAIN_GRANT",
        subject=row.id,
        data={"from": body.from_product, "to": body.to_product, "purpose": body.purpose},
    )
    db.commit()
    return {"id": row.id, "purpose": row.purpose}


def _maintenance_snapshot(db: Session, caller: Principal) -> dict:
    pending = db.scalar(
        select(func.count()).select_from(Outbox).where(Outbox.tenant_id == caller.tenant_id, Outbox.status == "PENDING")
    )
    dead = db.scalar(select(func.count()).select_from(DeadLetter).where(DeadLetter.tenant_id == caller.tenant_id))
    models = db.scalar(select(func.count()).select_from(ModelVersion))
    db.execute(text("SELECT 1"))
    return {
        "service": "scourgeai",
        "version": VERSION,
        "live_dispatch": False,
        "llm_enabled": False,
        "worker_enabled": os.environ.get("TIC_WORKER") == "1",
        "database": "ok",
        "outbox_pending": int(pending or 0),
        "dead_letters": int(dead or 0),
        "model_count": int(models or 0),
        "limits": [
            "does not dispatch",
            "does not immobilise",
            "does not edit evidence",
            "does not enable a language model",
        ],
    }


@app.get("/v1/maintenance")
def maintenance(caller: Principal = Depends(principal), db: Session = Depends(db_session)):
    require_permission(caller, "platform.maintain")
    return _maintenance_snapshot(db, caller)


@app.post("/v1/maintenance/catalogue")
def refresh_catalogue(caller: Principal = Depends(principal), db: Session = Depends(db_session)):
    require_permission(caller, "platform.maintain")
    created = seed_reference_data(db)
    auditlog.record(
        db,
        tenant_id=caller.tenant_id,
        product=caller.product,
        actor=caller.actor,
        action="PLATFORM_CATALOGUE_REFRESH",
        subject="model_versions",
        data={"created": created},
    )
    db.commit()
    return {"created": created, "external_dispatch": False, "llm_enabled": False}


@app.post("/v1/maintenance/requeue")
def requeue(caller: Principal = Depends(principal), db: Session = Depends(db_session)):
    require_permission(caller, "platform.maintain")
    count = requeue_dead(db, caller.tenant_id)
    auditlog.record(
        db,
        tenant_id=caller.tenant_id,
        product=caller.product,
        actor=caller.actor,
        action="MAINTENANCE_REQUEUE",
        subject=caller.tenant_id,
        data={"requeued": count},
    )
    db.commit()
    return {"requeued": count, "external_dispatch": False}


@app.post("/v1/maintenance/models")
def update_model(body: ModelUpdateIn, caller: Principal = Depends(principal), db: Session = Depends(db_session)):
    require_permission(caller, "platform.maintain")
    row, created = register_model(db, body.name, body.version, body.kind, body.status, body.description)
    auditlog.record(
        db,
        tenant_id=caller.tenant_id,
        product=caller.product,
        actor=caller.actor,
        action="PLATFORM_MODEL_UPDATED",
        subject=row.id,
        data={"name": row.name, "version": row.version, "status": row.status, "created": created, "llm": False},
    )
    db.commit()
    return {
        "id": row.id,
        "name": row.name,
        "version": row.version,
        "kind": row.kind,
        "status": row.status,
        "description": row.description,
        "llm": False,
        "created": created,
    }
