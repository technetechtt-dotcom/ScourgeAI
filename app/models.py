"""Persistence models.

Existing table names are unchanged so a v0.2 SQLite file can be opened and
extended. `recommendations` is the AI recommendation store.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import declarative_base

Base = declarative_base()

ROLES = ("operator", "supervisor", "administrator", "service", "developer")
INCIDENT_STATUSES = ("OPEN", "IN_REVIEW", "CLOSED")


def now() -> datetime:
    return datetime.now(timezone.utc)


class Organisation(Base):
    __tablename__ = "organisations"
    id = Column(String(120), primary_key=True)
    name = Column(String(200), nullable=False)
    created_at = Column(DateTime(timezone=True), default=now, nullable=False)


class User(Base):
    __tablename__ = "users"
    id = Column(String(60), primary_key=True)
    organisation_id = Column(String(120), ForeignKey("organisations.id"), nullable=False, index=True)
    email = Column(String(254), nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(32), nullable=False)
    mfa_secret = Column(Text, nullable=True)
    mfa_enabled = Column(Boolean, nullable=False, default=False)
    recovery_hashes = Column(Text, nullable=True)
    failed_attempts = Column(Integer, nullable=False, default=0)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    last_login_host = Column(String(120), nullable=True)
    disabled = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), default=now, nullable=False)
    __table_args__ = (
        UniqueConstraint("organisation_id", "email", name="uq_user_org_email"),
        CheckConstraint(
            "role in ('operator','supervisor','administrator','service','developer')",
            name="ck_user_role",
        ),
    )


class SessionToken(Base):
    __tablename__ = "sessions"
    id = Column(String(60), primary_key=True)
    user_id = Column(String(60), ForeignKey("users.id"), nullable=False, index=True)
    token_hash = Column(String(64), nullable=False, unique=True)
    scope = Column(String(32), nullable=False, default="full")
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    client_host = Column(String(120), nullable=True)
    created_at = Column(DateTime(timezone=True), default=now, nullable=False)


class PasswordReset(Base):
    __tablename__ = "password_resets"
    id = Column(String(60), primary_key=True)
    user_id = Column(String(60), ForeignKey("users.id"), nullable=False, index=True)
    token_hash = Column(String(64), nullable=False, unique=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=now, nullable=False)


class DeviceCredential(Base):
    """Managed device HMAC credential. The secret is sealed. The plaintext is returned once."""

    __tablename__ = "device_credentials"
    id = Column(String(120), primary_key=True)
    tenant_id = Column(String(120), nullable=False, index=True)
    product = Column(String(32), nullable=False)
    status = Column(String(24), nullable=False, default="active")
    secret_sealed = Column(Text, nullable=False)
    last_sequence = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime(timezone=True), default=now, nullable=False)
    rotated_at = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)


class EventNonce(Base):
    __tablename__ = "event_nonces"
    id = Column(String(60), primary_key=True)
    tenant_id = Column(String(120), nullable=False)
    product = Column(String(32), nullable=False)
    nonce = Column(String(128), nullable=False)
    event_id = Column(String(120), nullable=False)
    created_at = Column(DateTime(timezone=True), default=now, nullable=False)
    __table_args__ = (UniqueConstraint("tenant_id", "product", "nonce", name="uq_event_nonce"),)


class DeviceKey(Base):
    """Metadata for a device key. Secret bytes stay in TIC_DEVICE_KEYS, not here."""

    __tablename__ = "device_keys"
    id = Column(String(120), primary_key=True)
    tenant_id = Column(String(120), nullable=False, index=True)
    product = Column(String(32), nullable=False)
    fingerprint = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), default=now, nullable=False)


class Event(Base):
    __tablename__ = "security_events"
    id = Column(String(120), primary_key=True)
    tenant_id = Column(String(120), nullable=False, index=True)
    product = Column(String(32), nullable=False)
    event_type = Column(String(100), nullable=False)
    subject_id = Column(String(120), nullable=False)
    occurred_at = Column(DateTime(timezone=True), nullable=False)
    received_at = Column(DateTime(timezone=True), default=now)
    payload = Column(JSON, nullable=False)
    raw_sha256 = Column(String(64), nullable=False)
    incident_id = Column(String(60), ForeignKey("incidents.id"), nullable=True)
    device_signature_verified = Column(Boolean, nullable=False, default=False)
    delayed = Column(Boolean, nullable=False, default=False)
    __table_args__ = (
        Index("ix_events_incident", "incident_id"),
        Index("ix_events_tenant_product_time", "tenant_id", "product", "occurred_at"),
    )


class Incident(Base):
    __tablename__ = "incidents"
    id = Column(String(60), primary_key=True)
    tenant_id = Column(String(120), nullable=False, index=True)
    product = Column(String(32), nullable=False)
    subject_id = Column(String(120), nullable=False)
    incident_type = Column(String(100), nullable=False)
    status = Column(String(24), nullable=False, default="OPEN")
    severity = Column(String(24), nullable=False, default="CONCERN")
    created_at = Column(DateTime(timezone=True), default=now)
    last_event_at = Column(DateTime(timezone=True), default=now)
    __table_args__ = (
        Index("ix_incidents_scope", "tenant_id", "product", "subject_id", "status"),
    )


class Assessment(Base):
    __tablename__ = "ai_assessments"
    id = Column(String(60), primary_key=True)
    incident_id = Column(String(60), ForeignKey("incidents.id"), nullable=False, index=True)
    tenant_id = Column(String(120), nullable=False, index=True)
    risk_level = Column(String(24), nullable=False)
    confidence = Column(String(40), nullable=False)
    observed = Column(JSON, nullable=False)
    inferred = Column(JSON, nullable=False)
    unknowns = Column(JSON, nullable=False)
    model_version = Column(String(50), nullable=False)
    created_at = Column(DateTime(timezone=True), default=now)


class Recommendation(Base):
    __tablename__ = "recommendations"
    id = Column(String(60), primary_key=True)
    incident_id = Column(String(60), ForeignKey("incidents.id"), nullable=False, index=True)
    tenant_id = Column(String(120), nullable=False, index=True)
    action = Column(String(200), nullable=False)
    status = Column(String(24), default="PENDING", nullable=False)
    reviewed_by = Column(String(120), nullable=True)
    review_note = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=now)


class Audit(Base):
    __tablename__ = "audit_log"
    id = Column(String(60), primary_key=True)
    tenant_id = Column(String(120), nullable=False, index=True)
    product = Column(String(32), nullable=True, index=True)
    actor = Column(String(120), nullable=False)
    action = Column(String(120), nullable=False)
    subject = Column(String(120), nullable=False)
    data = Column(JSON, nullable=False)
    created_at = Column(DateTime(timezone=True), default=now)
    __table_args__ = (Index("ix_audit_tenant_created", "tenant_id", "created_at"),)


class Evidence(Base):
    __tablename__ = "evidence"
    id = Column(String(60), primary_key=True)
    tenant_id = Column(String(120), nullable=False, index=True)
    incident_id = Column(String(60), ForeignKey("incidents.id"), nullable=False, index=True)
    event_id = Column(String(120), ForeignKey("security_events.id"), nullable=False)
    sha256 = Column(String(64), nullable=False)
    label = Column(String(200), nullable=False)
    created_at = Column(DateTime(timezone=True), default=now, nullable=False)


class DeviceState(Base):
    __tablename__ = "device_state"
    id = Column(String(60), primary_key=True)
    tenant_id = Column(String(120), nullable=False)
    product = Column(String(32), nullable=False)
    device_id = Column(String(120), nullable=False)
    subject_id = Column(String(120), nullable=False)
    last_event_type = Column(String(100), nullable=False)
    last_seen_at = Column(DateTime(timezone=True), nullable=False)
    tracker_role = Column(String(32), nullable=False, default="unknown")
    backup_observation = Column(String(64), nullable=False, default="NOT_OBSERVED")
    power_state = Column(String(32), nullable=False, default="unknown")
    gnss_status = Column(String(32), nullable=False, default="unknown")
    tamper_state = Column(String(32), nullable=False, default="unknown")
    data_quality = Column(String(40), nullable=False, default="missing")
    activated_by_backend = Column(Boolean, nullable=False, default=False)
    updated_at = Column(DateTime(timezone=True), default=now, nullable=False)
    __table_args__ = (
        UniqueConstraint("tenant_id", "product", "device_id", name="uq_device_state"),
    )


class ModelVersion(Base):
    __tablename__ = "model_versions"
    id = Column(String(60), primary_key=True)
    name = Column(String(120), nullable=False)
    version = Column(String(50), nullable=False)
    kind = Column(String(32), nullable=False)
    status = Column(String(32), nullable=False, default="active")
    description = Column(Text, nullable=False)
    llm = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), default=now, nullable=False)
    __table_args__ = (UniqueConstraint("name", "version", name="uq_model_version"),)


class AgentExecution(Base):
    __tablename__ = "agent_executions"
    id = Column(String(60), primary_key=True)
    tenant_id = Column(String(120), nullable=False, index=True)
    product = Column(String(32), nullable=True, index=True)
    incident_id = Column(String(60), ForeignKey("incidents.id"), nullable=True, index=True)
    agent_name = Column(String(80), nullable=False)
    status = Column(String(24), nullable=False)
    confidence = Column(String(40), nullable=False)
    uncertainty = Column(JSON, nullable=False)
    input_hash = Column(String(64), nullable=False)
    output = Column(JSON, nullable=False)
    error = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=now, nullable=False)


class Outbox(Base):
    __tablename__ = "outbox"
    id = Column(String(60), primary_key=True)
    tenant_id = Column(String(120), nullable=False, index=True)
    topic = Column(String(80), nullable=False)
    payload = Column(JSON, nullable=False)
    status = Column(String(24), nullable=False, default="PENDING", index=True)
    attempts = Column(Integer, nullable=False, default=0)
    last_error = Column(Text, nullable=True)
    idempotency_key = Column(String(160), nullable=False)
    created_at = Column(DateTime(timezone=True), default=now, nullable=False)
    processed_at = Column(DateTime(timezone=True), nullable=True)
    claimed_by = Column(String(80), nullable=True)
    claimed_at = Column(DateTime(timezone=True), nullable=True)
    __table_args__ = (UniqueConstraint("idempotency_key", name="uq_outbox_key"),)


class RateBucket(Base):
    __tablename__ = "rate_buckets"
    key = Column(String(200), primary_key=True)
    window_start = Column(DateTime(timezone=True), nullable=False)
    hits = Column(Integer, nullable=False, default=0)


class DeadLetter(Base):
    __tablename__ = "dead_letters"
    id = Column(String(60), primary_key=True)
    outbox_id = Column(String(60), nullable=False, index=True)
    tenant_id = Column(String(120), nullable=False)
    topic = Column(String(80), nullable=False)
    payload = Column(JSON, nullable=False)
    error = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=now, nullable=False)


class CrossDomainGrant(Base):
    __tablename__ = "cross_domain_grants"
    id = Column(String(60), primary_key=True)
    tenant_id = Column(String(120), nullable=False, index=True)
    from_product = Column(String(32), nullable=False)
    to_product = Column(String(32), nullable=False)
    purpose = Column(String(200), nullable=False)
    granted_by = Column(String(120), nullable=False)
    created_at = Column(DateTime(timezone=True), default=now, nullable=False)
    __table_args__ = (
        UniqueConstraint("tenant_id", "from_product", "to_product", name="uq_cross_domain_grant"),
    )
