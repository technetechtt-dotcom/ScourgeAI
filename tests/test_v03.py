import json
import os
import subprocess
import sys
import time
import hmac
import hashlib
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from tests.test_api import client, send
from sqlalchemy import select

from app import engine, security
from app.accounts import create_user
from app.db import SessionLocal, build_engine
from app.models import Base, DeadLetter, Outbox
from app.outbox import process_outbox
from app.seed import seed_demo_accounts
from app.vehicle import classify_event, evaluate_backup_policy


def credentials(product="guardian", tenant="tenant-a"):
    secret = "secret-guardian" if product == "guardian" else "secret-arx"
    return {"params": {"tenant_id": tenant, "product": product}, "headers": {"X-Client-Secret": secret}}


def signed_event(event_id, product, event_type, subject, **overrides):
    data = {
        "schema_version": "1.0",
        "event_id": event_id,
        "event_type": event_type,
        "source_product": product,
        "tenant_id": overrides.pop("tenant", "tenant-a"),
        "subject_type": "person" if product == "guardian" else "vehicle",
        "subject_id": subject,
        "occurred_at": overrides.pop("occurred_at", "2026-10-22T12:00:00Z"),
        "source": overrides.pop("source", {}),
        "observation": overrides.pop("observation", {}),
        "integrity": {},
    }
    body = json.dumps(data, separators=(",", ":")).encode()
    secret = overrides.pop("secret", "secret-guardian" if product == "guardian" else "secret-arx")
    ts = str(int(time.time()))
    signature = hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    headers = {"X-Event-Timestamp": ts, "X-Event-Signature": signature, "Content-Type": "application/json"}
    nonce = overrides.pop("nonce", event_id)
    if nonce:
        headers["X-Event-Nonce"] = nonce
    if "device_key" in overrides:
        headers["X-Device-Key-Id"] = overrides["device_key"]
        headers["X-Device-Signature"] = overrides["device_sig"]
    return client.post("/v1/events", content=body, headers=headers)


def test_postgres_engine_pool_is_configured():
    database = build_engine("postgresql+psycopg://techne:techne@127.0.0.1:5432/techne")
    try:
        assert database.dialect.name == "postgresql"
        assert database.pool.size() == 5
    finally:
        database.dispose()


def test_rate_limiter_blocks_after_limit():
    limiter = security.RateLimiter(2, 60)
    assert limiter.allow("bucket") is True
    assert limiter.allow("bucket") is True
    assert limiter.allow("bucket") is False


def test_malformed_delayed_duplicate_and_conflict():
    assert client.post("/v1/events", content=b"{", headers={"Content-Type": "application/json"}).status_code == 422
    delayed = signed_event(
        "v03-delayed",
        "guardian",
        "device.heartbeat",
        "delay-person",
        occurred_at=(datetime.now(timezone.utc) - timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    assert delayed.status_code == 201
    assert delayed.json()["delayed"] is True
    first = signed_event("v03-dup", "guardian", "device.heartbeat", "dup-person")
    assert signed_event("v03-dup", "guardian", "device.heartbeat", "dup-person").json()["duplicate"] is True
    conflict = signed_event("v03-dup", "guardian", "device.location_updated", "dup-person")
    assert conflict.status_code == 409
    assert first.status_code == 201


def test_replay_nonce_and_spoofed_device_signature(monkeypatch):
    assert signed_event("v03-nonce-1", "guardian", "device.heartbeat", "nonce-person", nonce="n-1").status_code == 201
    replay = signed_event("v03-nonce-2", "guardian", "device.heartbeat", "nonce-person", nonce="n-1")
    assert replay.status_code == 409
    missing_nonce = signed_event("v03-nonce-missing", "guardian", "device.heartbeat", "nonce-person", nonce="")
    assert missing_nonce.status_code == 422
    monkeypatch.setenv(
        "TIC_DEVICE_KEYS",
        json.dumps({"tracker-1": {"secret": "device-secret-value", "tenant_id": "tenant-a", "product": "arxvigil"}}),
    )
    spoofed = signed_event(
        "v03-spoof",
        "arxvigil",
        "device.tamper",
        "spoof-vehicle",
        device_key="tracker-1",
        device_sig="0" * 64,
        source={"device_id": "tracker-1"},
    )
    assert spoofed.status_code == 401
    body = json.dumps(
        {
            "schema_version": "1.0",
            "event_id": "v03-signed-device",
            "event_type": "device.tamper",
            "source_product": "arxvigil",
            "tenant_id": "tenant-a",
            "subject_type": "vehicle",
            "subject_id": "signed-vehicle",
            "occurred_at": "2026-10-22T12:00:00Z",
            "source": {"device_id": "tracker-1"},
            "observation": {},
            "integrity": {},
        },
        separators=(",", ":"),
    ).encode()
    device_sig = hmac.new(b"device-secret-value", body, hashlib.sha256).hexdigest()
    ts = str(int(time.time()))
    client_sig = hmac.new(b"secret-arx", ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    accepted = client.post(
        "/v1/events",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-Event-Timestamp": ts,
            "X-Event-Signature": client_sig,
            "X-Event-Nonce": "v03-signed-device",
            "X-Device-Key-Id": "tracker-1",
            "X-Device-Signature": device_sig,
        },
    )
    assert accepted.status_code == 201
    assert accepted.json()["device_signature_verified"] is True


def test_signal_classes_backup_policy_and_no_backend_activation():
    missing = SimpleNamespace(event_type="device.gnss_integrity", payload={"observation": {}}, device_signature_verified=False)
    contradictory = SimpleNamespace(
        event_type="device.tamper",
        payload={"observation": {"conflict": True}},
        device_signature_verified=True,
    )
    confirmed = SimpleNamespace(
        event_type="device.tamper",
        payload={"observation": {"sensor": "lid"}},
        device_signature_verified=True,
        id="e1",
        occurred_at=datetime.now(timezone.utc),
    )
    assert classify_event(missing) == "missing"
    assert classify_event(contradictory) == "contradictory"
    assert classify_event(confirmed) == "confirmed_hardware_event"
    loss = SimpleNamespace(id="loss", event_type="device.primary_signal_lost", occurred_at=datetime.now(timezone.utc) - timedelta(seconds=30))
    pending = evaluate_backup_policy([loss])
    assert pending["state"] == "NOT_OBSERVED"
    assert pending["activated_by_backend"] is False
    backup = SimpleNamespace(id="backup", event_type="device.backup_activated", occurred_at=datetime.now(timezone.utc))
    observed = evaluate_backup_policy([loss, backup])
    assert observed["state"] == "CONFIRMED_BY_DEVICE_EVENT"
    assert observed["activated_by_backend"] is False
    ingested = signed_event(
        "v03-jscore",
        "arxvigil",
        "device.jscore.telemetry",
        "jam-vehicle",
        source={"device_id": "core-9"},
        observation={"supply_voltage": 12.4},
    )
    assert ingested.status_code == 201
    devices = client.get("/v1/devices", **credentials("arxvigil")).json()
    match = next(item for item in devices if item["device_id"] == "core-9")
    assert match["activated_by_backend"] is False
    assert match["tracker_role"] == "core"


def test_sos_is_kept_when_rules_fail(monkeypatch):
    def explode(_events):
        raise RuntimeError("provider down")

    monkeypatch.setattr(engine, "assess", explode)
    response = send("v03-sos-outage", "guardian", "sos.manual", subject="outage-person")
    assert response.status_code == 201
    assert response.json()["risk_level"] == "EMERGENCY"
    assert response.json()["live_dispatch"] is False
    assert response.json()["assessment_degraded"] is True


def test_governance_blocks_immobilisation_and_routes_do_not_expose_it():
    from app.agents.specialists import AGENTS

    blocked = AGENTS["ai_governance"].run({"proposed_action": "activate_immobilisation"})
    assert blocked.status == "blocked"
    assert blocked.output["executed"] is False
    paths = " ".join(getattr(route, "path", "") for route in client.app.routes).lower()
    assert "immobil" not in paths
    assert client.post("/v1/evidence", **credentials()).status_code == 405


def enroll(organisation_id, email, password="correct-horse-battery"):
    from app.totp import totp_code

    started = client.post(
        "/v1/auth/login",
        json={"organisation_id": organisation_id, "email": email, "password": password},
    )
    assert started.status_code == 200, started.text
    body = started.json()
    if body.get("access_token"):
        return body["access_token"]
    assert body["mfa_enrollment_required"] is True
    headers = {"Authorization": "Bearer " + body["enrollment_token"]}
    enrolled = client.post("/v1/auth/mfa/enroll", headers=headers)
    assert enrolled.status_code == 200, enrolled.text
    confirmed = client.post(
        "/v1/auth/mfa/confirm",
        headers=headers,
        json={"code": totp_code(enrolled.json()["secret"])},
    )
    assert confirmed.status_code == 200, confirmed.text
    assert len(confirmed.json()["recovery_codes"]) == 8
    return confirmed.json()["access_token"]


def test_cross_tenant_user_cannot_read_other_organisation():
    with SessionLocal() as db:
        create_user(db, "tenant-b", "bee@example.com", "correct-horse-battery", "operator")
        db.commit()
    token = enroll("tenant-b", "bee@example.com")
    incident = send("v03-tenant-wall", "guardian", "sos.volume", subject="walled-person").json()["incident_id"]
    denied = client.get(
        "/v1/incidents/" + incident,
        params={"tenant_id": "tenant-a", "product": "guardian"},
        headers={"Authorization": "Bearer " + token},
    )
    assert denied.status_code == 403
    own = client.get(
        "/v1/incidents",
        params={"tenant_id": "tenant-b", "product": "guardian"},
        headers={"Authorization": "Bearer " + token},
    )
    assert own.status_code == 200
    assert all(item["tenant_id"] == "tenant-b" for item in own.json())
    assert client.get("/v1/users", params={"tenant_id": "tenant-b", "product": "guardian"}, headers={"Authorization": "Bearer " + token}).status_code == 403


def _privileged_token(email, role):
    with SessionLocal() as db:
        create_user(db, "tenant-a", email, "correct-horse-battery", role)
        db.commit()
    return enroll("tenant-a", email)


def test_mfa_and_role_permissions():
    admin = _privileged_token("admin@example.com", "administrator")
    headers = {"Authorization": "Bearer " + admin}
    created = client.post(
        "/v1/users",
        params={"tenant_id": "tenant-a", "product": "guardian"},
        headers=headers,
        json={"email": "op@example.com", "password": "correct-horse-battery", "role": "operator"},
    )
    assert created.status_code == 201
    assert client.post(
        "/v1/users",
        **credentials(),
        json={"email": "nope@example.com", "password": "correct-horse-battery", "role": "operator"},
    ).status_code == 403
    operator = enroll("tenant-a", "op@example.com")
    incident = send("v03-review-sos", "guardian", "sos.duress", subject="review-person").json()["incident_id"]
    detail = client.get("/v1/incidents/" + incident, **credentials()).json()
    recommendation = detail["recommendations"][0]["id"]
    forbidden = client.post(
        "/v1/recommendations/" + recommendation + "/review",
        params={"tenant_id": "tenant-a", "product": "guardian"},
        headers={"Authorization": "Bearer " + operator},
        json={"status": "ACCEPTED", "reviewer": "should-be-ignored", "note": ""},
    )
    assert forbidden.status_code == 403
    supervisor = _privileged_token("super@example.com", "supervisor")
    accepted = client.post(
        "/v1/recommendations/" + recommendation + "/review",
        params={"tenant_id": "tenant-a", "product": "guardian"},
        headers={"Authorization": "Bearer " + supervisor},
        json={"status": "ACCEPTED", "reviewer": "spoofed-name", "note": "checked"},
    )
    assert accepted.status_code == 200
    assert accepted.json()["action_executed"] is False
    assert accepted.json()["reviewed_by"] == "super@example.com"
    service_event = send("v03-service-review", "guardian", "sos.manual", subject="service-review-person")
    service_detail = client.get("/v1/incidents/" + service_event.json()["incident_id"], **credentials()).json()
    service_review = client.post(
        "/v1/recommendations/" + service_detail["recommendations"][0]["id"] + "/review",
        **credentials(),
        json={"status": "REJECTED", "reviewer": "spoofed-operator", "note": "ignored"},
    )
    assert service_review.status_code == 200
    assert service_review.json()["reviewed_by"] == "client:guardian"


def test_copilot_questions_handover_and_responder_status():
    created = send("v03-question", "guardian", "sos.safeword", subject="question-person")
    incident = created.json()["incident_id"]
    brief = client.get(f"/v1/incidents/{incident}/brief", **credentials()).json()
    assert brief["llm_enabled"] is False
    assert brief["known_facts"]
    refused = client.post(
        f"/v1/incidents/{incident}/questions",
        **credentials(),
        json={"question": "Please dispatch responders and suppress the SOS"},
    ).json()
    assert refused["grounded"] is False
    assert refused["llm_enabled"] is False
    answered = client.post(
        f"/v1/incidents/{incident}/questions",
        **credentials(),
        json={"question": "Was there an SOS?"},
    ).json()
    assert answered["grounded"] is True
    assert "v03-question" in answered["sources"]
    handover = client.get(f"/v1/incidents/{incident}/handover", **credentials()).json()
    assert handover["ai_generated"] is False
    assert handover["human_review_required"] is True
    status = signed_event("v03-responder", "guardian", "responder.status_updated", "question-person")
    assert status.status_code == 201
    assert status.json()["incident_id"] == incident
    updated = client.get(f"/v1/incidents/{incident}/brief", **credentials()).json()
    assert "No responder dispatched" in updated["not_performed"]


def test_outbox_is_idempotent_and_dead_letters_failing_work():
    created = signed_event("v03-outbox", "guardian", "device.heartbeat", "outbox-person")
    assert created.status_code == 201
    signed_event("v03-outbox", "guardian", "device.heartbeat", "outbox-person")
    with SessionLocal() as db:
        rows = list(db.scalars(select(Outbox).where(Outbox.idempotency_key == "event:v03-outbox")))
        assert len(rows) == 1
        result = process_outbox(db)
        assert result["external_dispatch"] is False
        assert result["processed"] >= 1
        failing = Outbox(
            id="dead-row",
            tenant_id="tenant-a",
            topic="event.ingested",
            payload={"fail": True},
            status="PENDING",
            attempts=0,
            idempotency_key="forced-failure",
        )
        db.add(failing)
        db.commit()
        for _ in range(5):
            process_outbox(db)
        assert db.get(Outbox, "dead-row").status == "DEAD"
        assert db.scalar(select(DeadLetter).where(DeadLetter.outbox_id == "dead-row")) is not None


def test_cross_domain_requires_a_grant():
    from app.divergence import cross_domain_divergence

    with SessionLocal() as db:
        result = cross_domain_divergence(db, "tenant-a", "nobody")
    assert result["compared"] is False
    assert result["event_ids"] == []
    assert result["theft_confirmed"] is False


def test_sqlite_backup_round_trip(tmp_path):
    from app.backup import backup_sqlite, restore_sqlite

    source = tmp_path / "source.db"
    copy = tmp_path / "copy.db"
    restored = tmp_path / "restored.db"
    database = build_engine("sqlite:///" + source.as_posix())
    Base.metadata.create_all(database)
    database.dispose()
    backup_sqlite(source.as_posix(), copy.as_posix())
    restore_sqlite(copy.as_posix(), restored.as_posix())
    assert restored.stat().st_size > 0


def test_alembic_upgrade_creates_tables(tmp_path):
    url = "sqlite:///" + (tmp_path / "migrated.db").as_posix()
    env = os.environ.copy()
    env["DATABASE_URL"] = url
    completed = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=os.path.dirname(os.path.dirname(__file__)),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    database = build_engine(url)
    try:
        names = set(Base.metadata.tables)
        present = set(__import__("sqlalchemy").inspect(database).get_table_names())
        assert names <= present
    finally:
        database.dispose()


def test_cli_creates_administrator(tmp_path):
    url = "sqlite:///" + (tmp_path / "cli.db").as_posix()
    env = os.environ.copy()
    env["DATABASE_URL"] = url
    completed = subprocess.run(
        [sys.executable, "-m", "app.cli", "create-admin", "--org", "cli-org", "--email", "root@example.com", "--password", "correct-horse-battery"],
        cwd=os.path.dirname(os.path.dirname(__file__)),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "root@example.com" in completed.stdout


def test_short_password_explains_the_rejection():
    response = client.post(
        "/v1/auth/login",
        json={"organisation_id": "demo", "email": "developer@example.com", "password": "short"},
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "password: String should have at least 12 characters"


def test_login_ignores_surrounding_spaces_and_accepts_the_organisation_name():
    with SessionLocal() as db:
        seed_demo_accounts(db)
        db.commit()
    response = client.post(
        "/v1/auth/login",
        json={
            "organisation_id": " ScourgeAI Demo ",
            "email": " supervisor@example.com ",
            "password": " correct-horse-battery ",
        },
    )
    assert response.status_code == 200
    assert response.json()["role"] == "supervisor"
    assert response.json()["mfa_enrollment_required"] is True
    assert response.json()["access_token"] is None


def test_stored_authenticator_requires_a_current_code():
    from app.crypto import seal
    from app.totp import random_secret, totp_code

    with SessionLocal() as db:
        create_user(db, "tenant-a", "mfa-user@example.com", "correct-horse-battery", "operator")
        from app.models import User

        user = db.scalar(select(User).where(User.email == "mfa-user@example.com"))
        secret = random_secret()
        user.mfa_enabled = True
        user.mfa_secret = seal(secret)
        user.last_login_host = "10.1.1.1"
        db.commit()
    missing = client.post(
        "/v1/auth/login",
        json={"organisation_id": "tenant-a", "email": "mfa-user@example.com", "password": "correct-horse-battery"},
    )
    assert missing.status_code == 401
    accepted = client.post(
        "/v1/auth/login",
        json={
            "organisation_id": "tenant-a",
            "email": "mfa-user@example.com",
            "password": "correct-horse-battery",
            "totp": totp_code(secret),
        },
    )
    assert accepted.status_code == 200
    assert accepted.json()["access_token"]
    assert accepted.json()["security_alert"] == "Sign-in from a new client address."


def test_demo_accounts_cover_each_human_role():
    with SessionLocal() as db:
        seed_demo_accounts(db)
        db.commit()
    expected = {
        ("demo", "operator@example.com"): "operator",
        ("demo", "supervisor@example.com"): "supervisor",
        ("demo", "admin@example.com"): "administrator",
        ("demo", "developer@example.com"): "developer",
        ("field", "field.operator@example.com"): "operator",
    }
    for (organisation_id, email), role in expected.items():
        response = client.post(
            "/v1/auth/login",
            json={"organisation_id": organisation_id, "email": email, "password": "correct-horse-battery"},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["role"] == role
        assert body["organisation_id"] == organisation_id
        assert body["mfa_enrollment_required"] is True
        assert body["access_token"] is None
        assert body["enrollment_token"]
    wrong_org = client.post(
        "/v1/auth/login",
        json={"organisation_id": "field", "email": "admin@example.com", "password": "correct-horse-battery"},
    )
    assert wrong_org.status_code == 401
    developer = enroll("demo", "developer@example.com")
    headers = {"Authorization": "Bearer " + developer}
    params = {"tenant_id": "demo", "product": "guardian"}
    assert client.get("/v1/incidents", params=params, headers=headers).status_code == 200
    assert client.get("/v1/users", params=params, headers=headers).status_code == 200
    assert client.get("/v1/maintenance", params=params, headers=headers).status_code == 200
    review = client.post(
        "/v1/recommendations/missing/review",
        params=params,
        headers=headers,
        json={"status": "ACCEPTED", "reviewer": "developer@example.com", "note": ""},
    )
    assert review.status_code == 404
    operator = enroll("demo", "operator@example.com")
    assert client.get("/v1/users", params=params, headers={"Authorization": "Bearer " + operator}).status_code == 403
    admin = enroll("demo", "admin@example.com")
    assert client.get("/v1/maintenance", params=params, headers={"Authorization": "Bearer " + admin}).status_code == 403


def test_dashboard_pages_and_metrics():
    page = client.get("/dashboard")
    assert page.status_code == 200
    for label in (
        "ScourgeAI",
        "Live Incidents",
        "Guardian Intelligence",
        "ArxVigil Intelligence",
        "Evidence Management",
        "Platform maintenance",
        "NOT A LIVE EMERGENCY SYSTEM",
        "Push feed",
    ):
        assert label in page.text
    assert client.get("/ready").json()["ready"] is True
    assert "scourgeai_live_dispatch_enabled 0" in client.get("/metrics").text
    monitor = client.get("/v1/monitoring", **credentials()).json()
    assert monitor["live_dispatch"] is False
    assert monitor["llm_enabled"] is False
    assert monitor["simulated"] is False


def test_developer_maintains_the_platform_without_dispatch():
    developer = _privileged_token("developer-maintainer@example.com", "developer")
    headers = {"Authorization": "Bearer " + developer}
    params = {"tenant_id": "tenant-a", "product": "guardian"}
    created = client.post(
        "/v1/users",
        params=params,
        headers=headers,
        json={"email": "maintained@example.com", "password": "correct-horse-battery", "role": "operator"},
    )
    assert created.status_code == 201
    user_id = created.json()["id"]
    changed = client.post(
        "/v1/users/" + user_id,
        params=params,
        headers=headers,
        json={"role": "supervisor", "disabled": True},
    )
    assert changed.status_code == 200
    assert changed.json()["disabled"] is True
    blocked = client.post(
        "/v1/auth/login",
        json={"organisation_id": "tenant-a", "email": "maintained@example.com", "password": "correct-horse-battery"},
    )
    assert blocked.status_code == 401
    self_update = client.post("/v1/users/missing-self", params=params, headers=headers, json={"disabled": True})
    assert self_update.status_code == 404
    me = client.get("/v1/auth/me", params=params, headers=headers).json()
    listed = client.get("/v1/users", params=params, headers=headers).json()
    own = next(row for row in listed if row["email"] == me["actor"])
    assert client.post(
        "/v1/users/" + own["id"],
        params=params,
        headers=headers,
        json={"disabled": True},
    ).status_code == 409
    incident = send("v03-developer-sos", "guardian", "sos.duress", subject="developer-review").json()["incident_id"]
    detail = client.get("/v1/incidents/" + incident, params=params, headers=headers).json()
    recommendation = detail["recommendations"][0]["id"]
    accepted = client.post(
        "/v1/recommendations/" + recommendation + "/review",
        params=params,
        headers=headers,
        json={"status": "ACCEPTED", "reviewer": "spoofed", "note": "developer review"},
    )
    assert accepted.status_code == 200
    assert accepted.json()["action_executed"] is False
    assert accepted.json()["reviewed_by"] == "developer-maintainer@example.com"
    status = client.post(
        "/v1/incidents/" + incident + "/status",
        params=params,
        headers=headers,
        json={"status": "IN_REVIEW", "note": "developer status"},
    )
    assert status.status_code == 200
    assert status.json()["action_executed"] is False
    grant = client.post(
        "/v1/grants",
        params=params,
        headers=headers,
        json={"from_product": "guardian", "to_product": "arxvigil", "purpose": "developer maintenance check"},
    )
    assert grant.status_code == 201
    catalogue = client.post("/v1/maintenance/catalogue", params=params, headers=headers)
    assert catalogue.status_code == 200
    assert catalogue.json()["external_dispatch"] is False
    assert catalogue.json()["llm_enabled"] is False
    registered = client.post(
        "/v1/maintenance/models",
        params=params,
        headers=headers,
        json={
            "name": "maintenance-rules",
            "version": "v1",
            "kind": "rules",
            "status": "active",
            "description": "Registered by the developer account.",
        },
    )
    assert registered.status_code == 200
    assert registered.json()["llm"] is False
    assert registered.json()["created"] is True
    updated = client.post(
        "/v1/maintenance/models",
        params=params,
        headers=headers,
        json={
            "name": "maintenance-rules",
            "version": "v1",
            "kind": "rules",
            "status": "retired",
            "description": "Retired by the developer account.",
        },
    )
    assert updated.status_code == 200
    assert updated.json()["created"] is False
    assert updated.json()["status"] == "retired"
    assert updated.json()["llm"] is False
    rejected = client.post(
        "/v1/maintenance/models",
        params=params,
        headers=headers,
        json={
            "name": "maintenance-rules",
            "version": "v1",
            "kind": "rules",
            "status": "active",
            "description": "Cannot enable a model.",
            "llm": True,
        },
    )
    assert rejected.status_code == 422
    with SessionLocal() as db:
        db.add(
            Outbox(
                id="developer-dead",
                tenant_id="tenant-a",
                topic="event.ingested",
                payload={"incident_id": incident},
                status="DEAD",
                attempts=5,
                idempotency_key="developer-dead-letter",
            )
        )
        db.commit()
    requeued = client.post("/v1/maintenance/requeue", params=params, headers=headers)
    assert requeued.status_code == 200
    assert requeued.json()["requeued"] >= 1
    assert requeued.json()["external_dispatch"] is False
    with SessionLocal() as db:
        assert db.get(Outbox, "developer-dead").status == "PENDING"
    operator = _privileged_token("operator-no-maint@example.com", "operator")
    administrator = _privileged_token("admin-no-maint@example.com", "administrator")
    assert client.get(
        "/v1/maintenance",
        params=params,
        headers={"Authorization": "Bearer " + operator},
    ).status_code == 403
    assert client.post(
        "/v1/maintenance/requeue",
        params=params,
        headers={"Authorization": "Bearer " + administrator},
    ).status_code == 403
    snapshot = client.get("/v1/maintenance", params=params, headers=headers).json()
    assert snapshot["live_dispatch"] is False
    assert snapshot["llm_enabled"] is False
    assert "does not immobilise" in snapshot["limits"]


def test_lockout_recovery_reset_sessions_and_production_guards(monkeypatch):
    from app.security import assert_production_configuration

    with SessionLocal() as db:
        create_user(db, "tenant-a", "lockout@example.com", "correct-horse-battery", "operator")
        create_user(db, "tenant-a", "reset-admin@example.com", "correct-horse-battery", "administrator")
        create_user(db, "tenant-a", "reset-target@example.com", "correct-horse-battery", "operator")
        db.commit()
    for _ in range(5):
        failed = client.post(
            "/v1/auth/login",
            json={"organisation_id": "tenant-a", "email": "lockout@example.com", "password": "wrong-password-value"},
        )
        assert failed.status_code == 401
    locked = client.post(
        "/v1/auth/login",
        json={"organisation_id": "tenant-a", "email": "lockout@example.com", "password": "correct-horse-battery"},
    )
    assert locked.status_code == 423
    admin = enroll("tenant-a", "reset-admin@example.com")
    headers = {"Authorization": "Bearer " + admin}
    params = {"tenant_id": "tenant-a", "product": "guardian"}
    people = client.get("/v1/users", params=params, headers=headers).json()
    target = next(row for row in people if row["email"] == "reset-target@example.com")
    issued = client.post("/v1/users/" + target["id"] + "/password-reset", params=params, headers=headers)
    assert issued.status_code == 200
    reset = client.post(
        "/v1/auth/password/reset",
        json={"token": issued.json()["reset_token"], "password": "replacement-battery"},
    )
    assert reset.status_code == 200
    old = client.post(
        "/v1/auth/login",
        json={"organisation_id": "tenant-a", "email": "reset-target@example.com", "password": "correct-horse-battery"},
    )
    assert old.status_code == 401
    sessions = client.get("/v1/auth/sessions", params=params, headers=headers)
    assert sessions.status_code == 200
    assert any(row["current"] for row in sessions.json())
    others = client.post("/v1/auth/sessions/revoke-others", params=params, headers=headers)
    assert others.status_code == 200
    monkeypatch.setenv("TIC_ENV", "production")
    monkeypatch.setenv("TIC_DATA_KEY", "production-data-key-value")
    monkeypatch.setenv("TIC_CLIENT_SECRETS", json.dumps({"demo:guardian": "development-change-me"}))
    try:
        assert_production_configuration()
        raised = False
    except RuntimeError:
        raised = True
    assert raised is True
    monkeypatch.setenv("TIC_ENV", "development")
    monkeypatch.setenv("TIC_REQUIRE_DEVICE_SIGNATURE", "1")
    denied = signed_event("v03-device-required", "guardian", "device.heartbeat", "device-required")
    assert denied.status_code == 401


def test_tenant_isolation_covers_the_read_endpoints():
    with SessionLocal() as db:
        create_user(db, "tenant-b", "isolation@example.com", "correct-horse-battery", "operator")
        db.commit()
    token = enroll("tenant-b", "isolation@example.com")
    headers = {"Authorization": "Bearer " + token}
    paths = (
        "/v1/incidents",
        "/v1/evidence",
        "/v1/devices",
        "/v1/recommendations",
        "/v1/audit",
        "/v1/monitoring",
        "/v1/auth/sessions",
        "/v1/users",
        "/v1/maintenance",
    )
    for path in paths:
        response = client.get(path, params={"tenant_id": "tenant-a", "product": "guardian"}, headers=headers)
        assert response.status_code == 403, path


def test_shared_rate_limit_is_visible_to_another_session(monkeypatch):
    monkeypatch.setenv("TIC_RATE_LIMIT", "1")
    from app.security import allow_database

    key = "shared-window-test"
    with SessionLocal() as first:
        assert allow_database(first, key) is True
        first.commit()
    with SessionLocal() as second:
        assert allow_database(second, key) is False


def test_two_workers_claim_different_outbox_rows():
    from app.outbox import claim_pending, enqueue

    with SessionLocal() as db:
        enqueue(db, "tenant-a", "event.ingested", {"incident_id": "left"}, "claim-left")
        enqueue(db, "tenant-a", "event.ingested", {"incident_id": "right"}, "claim-right")
        db.commit()
    first = SessionLocal()
    second = SessionLocal()
    try:
        left = claim_pending(first, "worker-a", limit=1)
        first.commit()
        right = claim_pending(second, "worker-b", limit=1)
        second.commit()
        assert len(left) == 1 and len(right) == 1
        assert left[0].id != right[0].id
        assert left[0].claimed_by == "worker-a"
        assert right[0].claimed_by == "worker-b"
    finally:
        first.close()
        second.close()


def test_oidc_token_cannot_cross_tenants(monkeypatch):
    monkeypatch.setenv("TIC_OIDC_HMAC_SECRET", "oidc-secret-value")
    monkeypatch.setenv("TIC_OIDC_ISSUER", "https://idp.example")
    monkeypatch.setenv("TIC_OIDC_AUDIENCE", "techne")
    from app.oidc import issue_token

    token = issue_token(
        {
            "iss": "https://idp.example",
            "aud": "techne",
            "exp": int(time.time()) + 300,
            "organisation_id": "tenant-b",
            "email": "oidc@example.com",
            "role": "operator",
        },
        "oidc-secret-value",
    )
    headers = {"Authorization": "Bearer " + token}
    assert client.get("/v1/incidents", params={"tenant_id": "tenant-a", "product": "guardian"}, headers=headers).status_code == 403
    assert client.get("/v1/incidents", params={"tenant_id": "tenant-b", "product": "guardian"}, headers=headers).status_code == 200


def test_mtls_requirement_rejects_requests_without_a_peer_certificate(monkeypatch):
    from app.mtls import mtls_satisfied

    monkeypatch.setenv("TIC_MTLS_REQUIRED", "1")
    assert client.get("/health").status_code == 200
    assert client.get("/v1/incidents", **credentials()).status_code == 401
    assert mtls_satisfied({"extensions": {"tls": {"client_cert_chain": [b"cert"]}}}) is True
    assert mtls_satisfied({"extensions": {}}) is False


def test_language_model_gate_refuses_calls():
    import pytest

    from app.llm import LLMDisabled, complete

    with pytest.raises(LLMDisabled):
        complete("Summarise the incident", ["dash-sos-1"])


def test_backup_activation_decision_stays_on_the_device():
    import inspect

    import app.ingest as ingest
    from app.jamshield_device import local_backup_tracker_decision

    assert local_backup_tracker_decision(True, 9) == "wait"
    assert local_backup_tracker_decision(True, 10) == "activate_secondary_tracker_locally"
    source = inspect.getsource(ingest)
    assert "jamshield_device" not in source
    assert "activate_secondary_tracker_locally" not in source


def test_push_feed_emits_a_server_event():
    with client.stream(
        "GET",
        "/v1/stream",
        params={"tenant_id": "tenant-a", "product": "guardian", "once": 1},
        headers={"X-Client-Secret": "secret-guardian"},
    ) as response:
        assert response.status_code == 200
        body = response.read().decode()
    assert body.startswith("data:")
    assert '"live_dispatch": false' in body

